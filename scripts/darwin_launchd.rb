# Copyright (C) Juewuy

require 'cgi'
require 'digest'
require 'fileutils'
require 'open3'
require 'tmpdir'

class DarwinLaunchd
  LAUNCHCTL = '/bin/launchctl'.freeze
  attr_reader :log

  def initialize(home, scope)
    @home = File.realpath(home)
    @scope = scope
    @runtime = File.join(@home, 'runtime')
    @ready = File.join(@runtime, 'service.ready')
    @log = File.join(@home, 'logs', 'service.log')
    @label = "local.shellcrash.#{scope}.#{Digest::SHA256.hexdigest(@home)[0, 12]}"
    directory = scope == 'system' ? '/Library/LaunchDaemons' : File.expand_path('~/Library/LaunchAgents')
    @boot_plist = File.join(directory, "#{@label}.plist")
  end

  def pid
    job_pid(info(target))
  end

  def autostart?
    File.file?(@boot_plist)
  end

  def autostart(enabled)
    if enabled
      create_job(@boot_plist)
    else
      FileUtils.rm_f(@boot_plist)
    end
  end

  def start(mode, source)
    raise 'The ShellCrash service is already running' if pid

    stop
    service = target
    path = File.join(@runtime, 'service.plist')
    FileUtils.rm_f(@ready)
    create_job(path, mode, source)
    run!('bootstrap', service.split('/')[0...-1].join('/'), path)
    deadline = monotonic + 32
    loop do
      state = info(service)
      owner = job_pid(state)
      return owner if owner && File.file?(@ready) && File.read(@ready).to_i == owner
      break if monotonic >= deadline || (!owner && state.to_s.match?(/^\s+last exit code = \d+$/))

      sleep 0.2
    end

    stop
    raise "The ShellCrash service did not start. See #{@log}"
  end

  def stop
    service = target
    state = info(service)
    return unless state

    if job_pid(state)
      capture('kill', 'SIGTERM', service)
      deadline = monotonic + 45
      while job_pid(state = info(service))
        raise "The ShellCrash service did not complete shutdown. See #{@log}" if monotonic >= deadline

        sleep 0.2
      end
    end
    run!('bootout', service) if state
  end

  private

  def monotonic
    Process.clock_gettime(Process::CLOCK_MONOTONIC)
  end

  def target
    return "system/#{@label}" if @scope == 'system'

    uid = Process.euid
    user = "user/#{uid}"
    gui = "gui/#{uid}"
    return "#{gui}/#{@label}" if info("#{gui}/#{@label}")
    return "#{user}/#{@label}" if info("#{user}/#{@label}")

    "#{info(gui) ? gui : user}/#{@label}"
  end

  def info(service)
    output, _, result = capture('print', service)
    output if result.success?
  end

  def job_pid(state)
    state.to_s[/^\s+pid = (\d+)$/, 1]&.to_i
  end

  def capture(*args)
    Open3.capture3(LAUNCHCTL, *args)
  end

  def run!(*args)
    output, error, result = capture(*args)
    raise "launchctl #{args.first} failed: #{(error.empty? ? output : error).strip}" unless result.success?
  end

  def create_job(path, mode = nil, source = nil)
    FileUtils.mkdir_p(File.dirname(@log), mode: 0o700)
    File.open(@log, 'a', 0o600) {}
    FileUtils.mkdir_p(File.dirname(path), mode: 0o755)

    arguments = ['/usr/bin/ruby', File.join(@home, 'darwin.rb'), 'run', mode, source].compact
    fields = {
      'Label' => @label,
      'ProgramArguments' => arguments,
      'EnvironmentVariables' => { 'SHELLCRASH_HOME' => @home, 'SHELLCRASH_LAUNCHD' => '1' },
      'RunAtLoad' => true,
      'ExitTimeOut' => 45,
      'StandardOutPath' => @log,
      'StandardErrorPath' => @log
    }
    Dir.mktmpdir('shellcrash-job-', File.dirname(path)) do |directory|
      staged = File.join(directory, 'job.plist')
      File.write(staged, <<~XML)
        <?xml version="1.0" encoding="UTF-8"?>
        <!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
        <plist version="1.0">#{plist(fields)}</plist>
      XML
      raise 'Invalid launchd service definition' unless system('/usr/bin/plutil', '-lint', staged, out: File::NULL)

      File.chmod(0o644, staged)
      File.rename(staged, path)
    end
  end

  def plist(value)
    case value
    when String then "<string>#{CGI.escapeHTML(value)}</string>"
    when Integer then "<integer>#{value}</integer>"
    when TrueClass then '<true/>'
    when Array then "<array>#{value.map { |item| plist(item) }.join}</array>"
    when Hash
      "<dict>#{value.map { |key, item| "<key>#{CGI.escapeHTML(key)}</key>#{plist(item)}" }.join}</dict>"
    else raise ArgumentError, "Unsupported launchd plist value #{value.class}"
    end
  end
end
