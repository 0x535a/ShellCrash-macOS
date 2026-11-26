# Copyright (C) Juewuy

require 'digest'
require 'etc'
require 'fileutils'
require 'ipaddr'
require 'json'
require 'open3'
require 'optparse'
require 'shellwords'
require 'socket'
require 'tmpdir'
require 'yaml'
require 'zlib'

$stdout.sync = true

class DarwinShellCrash
  RELEASE = 'v1.19.34'.freeze
  ARM64_SHA256 = '1a7a20eca63fbbaec90137717465bfde488d0db2a3a79b8fadebf9b2545b6e4c'.freeze
  MODES = %w[pure redir tun mix bypass tproxy].freeze
  PF_MODES = %w[redir mix tproxy].freeze
  TUN_MODES = %w[tun mix].freeze
  FOREGROUND_MODES = (PF_MODES + ['bypass']).freeze
  SYSTEM_HOME = '/Library/Application Support/ShellCrash'.freeze
  SYSTEM_COMMAND = '/usr/local/bin/crash'.freeze

  def initialize
    @explicit_home = ENV['SHELLCRASH_HOME'] || ENV['CRASHDIR']
    @explicit_home ||= __dir__ if File.executable?(File.join(__dir__, 'bin', 'mihomo'))
    home = @explicit_home || (Process.euid.zero? ? SYSTEM_HOME : '~/Library/Application Support/ShellCrash')
    @home = File.expand_path(home)
    @bin = File.join(@home, 'bin', 'mihomo')
    @yamls = File.join(@home, 'yamls')
    @runtime = File.join(@home, 'runtime')
    @session_file = File.join(@runtime, 'session.json')
    @log = File.join(@home, 'logs', 'mihomo.log')
    @instance_file = File.join(@home, 'installation.json')
  end

  def call(args)
    args = ['menu'] if args.empty? && instance
    args.shift if args.first == '-s'
    command = args.shift || 'help'
    if system_reader? && (!%w[help --help -h menu status mode].include?(command) || (command == 'mode' && !args.empty?))
      raise "Run this operation with sudo #{Shellwords.escape(instance.fetch('command'))}"
    end
    case command
    when 'help', '--help', '-h' then help
    when 'menu' then menu
    when 'install' then install(args)
    when 'core' then locked { install_core(args) }
    when 'config' then locked { config(args) }
    when 'pf-rules' then preview_pf(args.shift)
    when 'mode'
      args.empty? ? select_mode(args) : locked { select_mode(args) }
    when 'check' then locked { check_mode(mode(args), args.shift) }
    when 'start', 'run' then launch(mode(args), args.shift, command == 'run')
    when 'stop' then locked { stop }
    when 'status' then system_reader? ? status : locked { status }
    when 'restart' then locked { restart(args) }
    else raise ArgumentError, "Unknown Darwin command #{command}. See help."
    end
    0
  end

  private

  def help
    puts <<~HELP
      ShellCrash for macOS
      install [mihomo.gz] [--sha256 SHA]  Install for the current user, or system-wide with sudo
        --scope user|system             Enable a managed installation at an explicit SHELLCRASH_HOME
        --command-dir DIR               Choose where to install the crash command
        --local-uid UID                 Choose the non-root user for local transparent proxying
      core [mihomo.gz [--sha256 SHA]]     Install the verified official release or local build
      config import FILE | fetch URL    Validate and save a complete Mihomo YAML
      check [pure|redir|tun|mix|bypass|tproxy] [FILE]
      pf-rules [redir|bypass]            Preview the configured PF rules
      run [pure|redir|tun|mix|bypass|tproxy] [FILE]
      mode [pure|redir|tun|mix|bypass|tproxy]
      start [pure|tun] [FILE]            Start the selected mode
      status | stop | restart [pure|tun] [FILE]
      crash --user / crash --system selects the installed instance.
      SHELLCRASH_HOME sets the configuration and data directory for direct scripts.
      Tun requires root and uses Mihomo's system routing.
      PF Redir requires root and uses configs/darwin-pf.yaml.
      Mix uses the same PF settings for TCP and UDP.
      Bypass uses the bypass section of configs/darwin-pf.yaml and no core.
      Tproxy is experimental PF TCP and UDP. It requires bin/feth-qemu.
    HELP
  end

  def menu
    return help unless $stdin.tty?
    return managed_menu if instance

    loop do
      puts "1. Status\n2. Start explicit proxy\n3. Stop\n4. Import Mihomo YAML"
      puts "5. Start Tun\n6. Run PF Redir\n7. Run Mix\n8. Run PF Bypass\n9. Run experimental PF Tproxy" if Process.euid.zero?
      puts '0. Exit'
      print '> '
      case $stdin.gets&.strip
      when '1' then locked { status }
      when '2' then launch('pure', nil, false)
      when '3' then locked { stop }
      when '4'
        print 'YAML file: '
        source = $stdin.gets&.strip
        locked { config(['import', source]) } if source && !source.empty?
      when '5' then launch('tun', nil, false) if Process.euid.zero?
      when '6' then launch('redir', nil, true) if Process.euid.zero?
      when '7' then launch('mix', nil, true) if Process.euid.zero?
      when '8' then launch('bypass', nil, true) if Process.euid.zero?
      when '9' then launch('tproxy', nil, true) if Process.euid.zero?
      when nil, '0' then break
      end
    rescue ArgumentError, RuntimeError, SystemCallError, Psych::Exception => error
      warn error.message
    end
  end

  def managed_menu
    loop do
      puts "ShellCrash (#{instance.fetch('scope')}): #{@home}"
      status if system_reader?
      puts "1. Start/restart\n2. Select connection mode (#{instance.fetch('mode')})\n3. Stop\n6. Import configuration\n8. Status\n0. Exit"
      print '> '
      case $stdin.gets&.strip
      when '1' then call(['restart'])
      when '2'
        choices = instance['scope'] == 'user' ? ['pure'] : MODES
        print "Mode (#{choices.join(', ')}): "
        value = $stdin.gets&.strip
        call(['mode', value]) if value && !value.empty?
      when '3' then call(['stop'])
      when '6'
        print 'YAML file: '
        source = $stdin.gets&.strip
        call(['config', 'import', source]) if source && !source.empty?
      when '8' then call(['status'])
      when nil, '0' then break
      end
    rescue ArgumentError, RuntimeError, SystemCallError, Psych::Exception => error
      warn error.message
    end
  end

  def locked
    FileUtils.mkdir_p(@runtime, mode: 0o700)
    File.open(File.join(@runtime, 'lock'), File::RDWR | File::CREAT, 0o600) do |lock|
      lock.flock(File::LOCK_EX)
      yield
    end
  end

  def mode(args)
    value = (args.shift || instance&.fetch('mode') || 'pure').downcase
    raise ArgumentError, "Darwin mode #{value} is not enabled; available: #{MODES.join(', ')}" unless MODES.include?(value)

    value
  end

  def install(args)
    scope = command_dir = local_uid = nil
    archive_options = []
    OptionParser.new do |parser|
      parser.on('--scope SCOPE', %w[user system]) { |value| scope = value }
      parser.on('--command-dir DIR') { |value| command_dir = File.expand_path(value) }
      parser.on('--local-uid UID', Integer) { |value| local_uid = value }
      parser.on('--sha256 SHA') { |value| archive_options.concat(['--sha256', value]) }
    end.parse!(args)
    next_scope = Process.euid.zero? ? 'system' : 'user'
    raise ArgumentError, "This installer is running with #{next_scope} privileges" if scope && scope != next_scope
    scope ||= next_scope if !@explicit_home || instance
    if !scope && (command_dir || local_uid)
      raise ArgumentError, 'Use --scope for a managed installation at a custom SHELLCRASH_HOME'
    end
    raise ArgumentError, '--local-uid is for a system installation' if local_uid && scope != 'system'

    old = instance
    raise 'The installation scope cannot change in place' if old && old['scope'] != scope
    command = if scope
                command_dir ? File.join(command_dir, 'crash') :
                  old&.fetch('command') || (scope == 'system' ? SYSTEM_COMMAND : user_command)
              end
    if scope == 'system'
      require_system_path(@home)
      require_system_path(File.dirname(command))
    end
    target_uid = if scope == 'system'
                   local_uid || old&.fetch('local-uid', nil) || Integer(ENV.fetch('SUDO_UID', '0'))
                 end
    if target_uid && !target_uid.zero?
      raise ArgumentError, 'Choose a non-root local UID' if target_uid.negative?
      Etc.getpwuid(target_uid)
    elsif local_uid
      raise ArgumentError, 'Choose a non-root local UID'
    end
    raise ArgumentError, 'ShellCrash paths must not contain newlines' if command && [command, @home].any? { |path| path.match?(/[\r\n]/) }
    check_command_path(command) if command

    locked do
      install_core(args + archive_options)
      FileUtils.mkdir_p(@yamls, mode: 0o700)
      %w[darwin.rb darwin_pf.py darwin_udp.py darwin_tcp.py darwin_tproxy.py menu.sh start.sh].each do |file|
        source = File.join(__dir__, file)
        destination = File.join(@home, file)
        FileUtils.install(source, destination, mode: 0o755) unless File.identical?(source, destination)
      end
      path = existing_config
      atomic_write(path, "mixed-port: 7890\nmode: rule\nrules:\n  - MATCH,DIRECT\n") unless File.exist?(path)
      if command
        File.chmod(0o755, @home) if scope == 'system'
        FileUtils.mkdir_p(File.dirname(command), mode: 0o755)
        check_command_path(command)
        atomic_write(command, command_script(scope), 0o755)
        atomic_write(@instance_file, JSON.generate('scope' => scope, 'mode' => old&.fetch('mode') || 'pure',
                                                    'command' => command, 'local-uid' => target_uid), 0o644)
      end
    end
    puts "Installed #{scope || 'standalone'} ShellCrash in #{@home}"
    if command
      register_user_path(File.dirname(command)) if scope == 'user' && command == user_command
      puts "Run: #{Shellwords.escape(command)}"
    else
      puts "Run: sh #{File.join(@home, 'menu.sh').inspect}"
    end
  end

  def instance
    JSON.parse(File.read(@instance_file)) if File.file?(@instance_file)
  end

  def system_reader?
    !Process.euid.zero? && instance&.fetch('scope') == 'system'
  end

  def user_command
    File.expand_path('~/.local/bin/crash')
  end

  def command_marker
    "# ShellCrash command for #{@home}"
  end

  def command_script(scope)
    <<~SH
      #!/bin/sh
      #{command_marker}
      scope=#{scope}
      if [ "$scope" = user ] && [ "$(/usr/bin/id -u)" -eq 0 ]; then
        echo 'Use a regular shell for a user installation, or run #{SYSTEM_COMMAND} with sudo.' >&2
        exit 1
      fi
      case "$1" in
        --user)
          shift
          if [ "$scope" = system ]; then
            if [ "$(/usr/bin/id -u)" -ne 0 ] && [ -x "$HOME/.local/bin/crash" ]; then
              exec "$HOME/.local/bin/crash" "$@"
            fi
            echo 'Select a user installation from its regular shell.' >&2
            exit 1
          fi
          ;;
        --system)
          shift
          if [ "$scope" = user ]; then
            if [ -x #{SYSTEM_COMMAND} ]; then
              exec #{SYSTEM_COMMAND} "$@"
            fi
            echo 'Install the system instance first.' >&2
            exit 1
          fi
          ;;
      esac
      unset CRASHDIR
      SHELLCRASH_HOME=#{Shellwords.escape(@home)}
      export SHELLCRASH_HOME
      exec /usr/bin/ruby #{Shellwords.escape(File.join(@home, 'darwin.rb'))} "$@"
    SH
  end

  def check_command_path(path)
    return unless File.exist?(path) || File.symlink?(path)
    if File.file?(path) && !File.symlink?(path)
      first, marker = File.open(path) { |file| [file.gets, file.gets] }
      return if first == "#!/bin/sh\n" && marker == "#{command_marker}\n"
    end

    raise "An existing command occupies #{path}"
  end

  def require_system_path(path)
    tree = File.expand_path(path)
    until tree == '/'
      if File.exist?(tree) || File.symlink?(tree)
        status = File.lstat(tree)
        unless status.directory? && status.uid.zero? && (status.mode & 0o022).zero?
          raise "System installation requires a root-owned directory: #{tree}"
        end
      end
      tree = File.dirname(tree)
    end
  end

  def register_user_path(directory)
    profile = case File.basename(ENV.fetch('SHELL', 'zsh'))
              when 'zsh' then '~/.zshrc'
              when 'bash' then '~/.bash_profile'
              when 'sh', 'dash', 'ksh' then '~/.profile'
              else return
              end
    path = File.expand_path(profile)
    mark = '# ShellCrash command path'
    return if File.file?(path) && File.read(path).lines.any? { |line| line.chomp == mark }

    File.open(path, 'a', 0o600) do |file|
      file.puts '', mark, "export PATH=#{Shellwords.escape(directory)}:\"$PATH\""
    end
    puts "Open a new terminal to use crash from #{profile}."
  end

  def select_mode(args)
    settings = instance or raise 'Install a managed ShellCrash instance first'
    return puts(settings.fetch('mode')) if args.empty?

    selected = mode(args)
    raise ArgumentError, 'Provide exactly one mode' unless args.empty?
    raise ArgumentError, 'A user installation can select only pure' if settings['scope'] == 'user' && selected != 'pure'

    atomic_write(@instance_file, JSON.generate(settings.merge('mode' => selected)), 0o644)
    puts "Selected #{selected} for the #{settings['scope']} instance"
  end

  def install_core(args)
    sha256 = nil
    OptionParser.new do |parser|
      parser.on('--sha256 SHA') { |value| sha256 = value }
    end.parse!(args)
    raise ArgumentError, 'Provide at most one Mihomo gzip archive' if args.size > 1

    archive = File.expand_path(args.first) unless args.empty?
    if sha256 && (!archive || !sha256.match?(/\A[0-9a-fA-F]{64}\z/))
      raise ArgumentError, '--sha256 requires a local gzip archive and a 64-character SHA-256 digest'
    end
    raise 'The pinned Darwin release currently supports Apple Silicon' unless `/usr/bin/uname -m`.strip == 'arm64'
    raise 'Stop the running instance before changing the core' if running_session

    FileUtils.mkdir_p(File.dirname(@bin), mode: 0o700)
    Dir.mktmpdir('core-', File.dirname(@bin)) do |temp|
      asset = "mihomo-darwin-arm64-#{RELEASE}.gz"
      staged = File.join(temp, asset)
      if archive
        FileUtils.cp(archive, staged)
      else
        download("https://github.com/MetaCubeX/mihomo/releases/download/#{RELEASE}/#{asset}", staged)
      end
      expected = sha256 ? sha256.downcase : ARM64_SHA256
      if Digest::SHA256.file(staged).hexdigest != expected
        raise "Mihomo archive SHA-256 does not match the #{sha256 ? 'supplied digest' : 'pinned release'}"
      end

      binary = File.join(temp, 'mihomo')
      Zlib::GzipReader.open(staged) do |gzip|
        File.open(binary, 'wb', 0o700) { |out| IO.copy_stream(gzip, out) }
      end
      unless File.binread(binary, 8)&.unpack('V2') == [0xfeedfacf, 0x0100000c]
        raise 'Expected an arm64 Mach-O Mihomo executable'
      end
      File.rename(binary, @bin)
    end
    source = sha256 ? 'local build' : RELEASE
    puts "Mihomo #{source} (darwin/arm64) verified"
  end

  def download(url, path, protocols = '=https')
    unless system('curl', '-q', '--fail', '--silent', '--show-error', '--location',
                  '--proto', protocols, '--proto-redir', protocols, '--connect-timeout', '15', '--max-time', '900',
                  '--output', path, '--', url)
      raise 'HTTPS download failed'
    end
  end

  def config(args)
    action, source = args
    raise ArgumentError, 'Use config import FILE or config fetch URL' unless %w[import fetch].include?(action) && source

    Dir.mktmpdir('config-', @runtime) do |temp|
      path = File.join(temp, 'input.yaml')
      action == 'fetch' ? download(source, path, '=http,https') : FileUtils.cp(File.expand_path(source), path)
      prepare_and_check('pure', path)
      FileUtils.mkdir_p(@yamls, mode: 0o700)
      atomic_write(File.join(@yamls, 'config.yaml'), File.binread(path))
    end
    puts 'Mihomo configuration saved'
  end

  def existing_config
    path = File.join(@yamls, 'config.yaml')
    legacy = File.join(@home, 'config.yaml')
    File.exist?(legacy) && !File.exist?(path) ? legacy : path
  end

  def atomic_write(path, contents, permissions = 0o600)
    Dir.mktmpdir('write-', File.dirname(path)) do |temp|
      file = File.join(temp, 'data')
      File.open(file, 'wb', permissions) { |out| out.write(contents) }
      File.chmod(permissions, file)
      File.rename(file, path)
    end
  end

  def map(document, label)
    node = document.root
    raise ArgumentError, "#{label} must be a YAML mapping" unless node.is_a?(Psych::Nodes::Mapping)

    node
  end

  def fields(node)
    node.children.each_slice(2).to_h { |key, value| [key.value, value] }
  end

  def assign(node, new_fields)
    names = new_fields.each_slice(2).map { |key, _| key.value }
    node.children.replace(node.children.each_slice(2).reject { |key, _| names.include?(key.value) }.flatten(1) + new_fields)
  end

  def values(hash)
    Psych.parse(YAML.dump(hash)).root.children
  end

  def effective(mode, source)
    source = source ? File.expand_path(source) : existing_config
    stream = Psych.parse_stream(File.read(source, encoding: 'UTF-8'))
    raise ArgumentError, 'Expected a single Mihomo YAML document' unless stream.children.size == 1

    settings = map(stream.children.first, 'Mihomo configuration')
    %w[user.yaml others.yaml].each do |name|
      file = File.join(@yamls, name)
      next unless File.file?(file)

      overlay = Psych.parse_file(file)
      assign(settings, map(overlay, name).children) if overlay
    end
    %w[rules proxies proxy-groups].each do |name|
      file = File.join(@yamls, "#{name}.yaml")
      next unless File.file?(file)

      fragment = Psych.parse_file(file)
      next unless fragment

      sequence = fragment.root
      base = fields(settings)[name]
      unless sequence.is_a?(Psych::Nodes::Sequence) && (base.nil? || base.is_a?(Psych::Nodes::Sequence))
        raise ArgumentError, "#{name}.yaml and its base setting must be sequences"
      end
      sequence.children.concat(base.children) if base
      assign(settings, [Psych::Nodes::Scalar.new(name), sequence])
    end

    loaded = YAML.safe_load(stream.yaml, aliases: true)
    Array(loaded['listeners']).each do |listener|
      if %w[tun redir tproxy].include?(listener['type'].to_s.downcase)
        raise ArgumentError, 'Use the ShellCrash mode to control transparent listeners instead of custom tun/redir/tproxy inbounds'
      end
    end
    tun = fields(settings)['tun']
    tun = Psych.parse('tun: {}').root.children.last unless tun.is_a?(Psych::Nodes::Mapping)
    if TUN_MODES.include?(mode)
      defaults = { 'stack' => 'system', 'auto-detect-interface' => mode == 'tun', 'dns-mode' => 'disabled', 'dns-hijack' => [] }
      defaults = defaults.reject { |key, _| fields(tun).key?(key) }
      assign(tun, values(defaults.merge('enable' => true, 'auto-route' => mode == 'tun', 'auto-redirect' => false)))
    else
      assign(tun, values('enable' => false))
    end
    assign(settings, [Psych::Nodes::Scalar.new('tun'), tun])

    ipv6_only = PF_MODES.include?(mode) && ipv6_redir? && Array(pf_config['targets']).empty?
    native_redir = PF_MODES.include?(mode) && !ipv6_only
    endpoints = { 'mixed-port' => loaded.fetch('mixed-port', 7890), 'redir-port' => native_redir ? redir_port : 0,
                  'tproxy-port' => 0, 'routing-mark' => 0, 'allow-lan' => false, 'bind-address' => '127.0.0.1' }
    endpoints['log-level'] = 'info' if mode == 'mix' && !%w[info debug].include?(loaded['log-level'])
    %w[external-controller external-controller-tls].each do |name|
      address = loaded[name].to_s
      next if address.empty?

      port = address.rpartition(':').last
      raise ArgumentError, "Invalid #{name} address" unless port.match?(/\A\d+\z/)

      endpoints[name] = "127.0.0.1:#{port}"
    end
    assign(settings, values(endpoints))
    ports = %w[mixed-port port socks-port].map { |name| Integer(endpoints.fetch(name) { loaded.fetch(name, 0) }) }.reject(&:zero?)
    if ports.any? { |port| !(1..65_535).cover?(port) } || ports.uniq != ports
      raise ArgumentError, 'Proxy listeners require distinct ports from 1 to 65535'
    end
    raise ArgumentError, 'Redir requires its own port' if PF_MODES.include?(mode) && ports.include?(endpoints['redir-port'])
    raise ArgumentError, 'Pure mode requires an HTTP, SOCKS5 or mixed port' if ports.empty? && mode == 'pure'

    [stream.yaml, ports]
  end

  def prepare_and_check(mode, source, directory = nil)
    if directory.nil?
      return Dir.mktmpdir('check-', @runtime) { |temp| prepare_and_check(mode, source, temp) }
    end
    raise 'Install the Mihomo core first (core command)' unless File.executable?(@bin)

    text, ports = effective(mode, source)

    file = File.join(directory, 'config.yaml')
    atomic_write(file, text)
    atomic_write(File.join(directory, 'udp-plan.json'), JSON.generate(tproxy_plan(text))) if mode == 'tproxy'
    if %w[redir mix].include?(mode) && ipv6_redir?
      atomic_write(File.join(directory, 'tcp6-plan.json'), JSON.generate(tcp6_plan(text)))
    end
    raise 'Mihomo configuration validation failed' unless system(@bin, '-t', '-d', @home, '-f', file)

    [file, ports]
  end

  def launch(mode, source, foreground)
    raise "Use run #{mode} in the foreground for the PF supervisor" if FOREGROUND_MODES.include?(mode) && !foreground
    return launch_bypass(source) if mode == 'bypass'

    return locked { start(mode, source, false) } unless foreground

    session = locked { start(mode, source, true) }
    interrupted = false
    signals = %w[INT TERM HUP].map { |name| [name, Signal.trap(name) { interrupted = true }] }
    worker = nil
    begin
      if PF_MODES.include?(mode)
        worker = mount_pf(session)
        wait_for_pf(worker) { interrupted }
      end
      until interrupted
        result = Process.waitpid2(session['pid'], Process::WNOHANG)
        if result
          raise "Mihomo exited with #{result.last}" unless result.last.success?

          break
        end
        if worker && IO.select([worker], nil, nil, 0)
          output = worker.read_nonblock(4096, exception: false)
          raise 'PF supervisor exited' if output.nil?

          print output unless output == :wait_readable
        end

        sleep 0.1
      end
    ensure
      begin
        release_pf(worker) if worker
      ensure
        stop_child(session['pid'])
        signals.each { |name, handler| Signal.trap(name, handler) }
        locked { remove_session(session) }
      end
    end
  end

  def wait_for_pf(worker)
    deadline = Process.clock_gettime(Process::CLOCK_MONOTONIC) + 16
    loop do
      raise 'PF did not report readiness' if yield || Process.clock_gettime(Process::CLOCK_MONOTONIC) > deadline
      next unless IO.select([worker], nil, nil, 0.2)

      announcement = worker.gets
      raise 'PF supervisor exited before installing its rules' unless announcement

      puts announcement
      return if announcement.include?('calls mounted')
    end
  end

  def release_pf(worker)
    worker.close_write
    puts worker.read
    worker.close
    raise 'PF supervisor reported an error' unless $?.success?
  end

  def start(mode, source, foreground)
    raise 'A ShellCrash instance is already running' if running_session
    if mode != 'pure' && !Process.euid.zero?
      raise "#{mode} requires root. Invoke the intended installation and config explicitly with sudo."
    end

    before = interfaces if TUN_MODES.include?(mode)
    directory = Dir.mktmpdir('mihomo-', @runtime)
    pid = nil
    begin
      file, ports = prepare_and_check(mode, source, directory)
      FileUtils.mkdir_p(File.dirname(@log), mode: 0o700)
      log_offset = File.exist?(@log) ? File.size(@log) : 0
      io = foreground && mode != 'mix' ? {} : { out: [@log, 'a', 0o600], err: [:child, :out] }
      pid = Process.spawn(@bin, '-d', @home, '-f', file, pgroup: true, in: File::NULL, **io)
      session = { 'pid' => pid, 'mode' => mode, 'config' => file, 'source' => source && File.expand_path(source), 'ports' => ports }
      if PF_MODES.include?(mode)
        session['supervisor'] = Process.pid
        session['supervisor-start'] = process_start(Process.pid)
      end
      deadline = Process.clock_gettime(Process::CLOCK_MONOTONIC) + 10
      native_port = YAML.safe_load(File.read(file), aliases: true).fetch('redir-port', 0)
      tcp_ports = native_port.zero? ? ports : ports + [native_port]
      loop do
        session['tun-device'] = started_tunnel(log_offset, before) if mode == 'mix'
        tunnel_ready = mode == 'mix' ? session['tun-device'] : mode != 'tun' || !(interfaces - before).empty?
        break if tunnel_ready && tcp_ports.all? { |port| core_ready?(pid, port) }

        if Process.waitpid(pid, Process::WNOHANG) || Process.clock_gettime(Process::CLOCK_MONOTONIC) > deadline
          raise "Mihomo did not start its #{mode} listeners. See #{@log}"
        end
        sleep 0.1
      end
      atomic_write(@session_file, JSON.generate(session))
      Process.detach(pid) unless foreground
      puts "Mihomo #{mode} running (PID #{pid})#{port_summary(session)}"
      puts "Mihomo log: #{@log}" if mode == 'mix'
      session
    rescue StandardError, SignalException
      stop_child(pid) if pid
      FileUtils.remove_entry_secure(directory)
      raise
    end
  end

  def started_tunnel(offset, before)
    name = File.binread(@log, nil, offset)[/Tun adapter listening at: (utun\d+)/, 1]
    name if name && (interfaces - before).include?(name)
  end

  def stop_child(pid)
    return if Process.waitpid(pid, Process::WNOHANG)

    signal(pid, 'TERM')
    50.times do
      return if Process.waitpid(pid, Process::WNOHANG)

      sleep 0.1
    end
    signal(pid, 'KILL')
    Process.waitpid(pid)
  rescue Errno::ECHILD
    nil
  end

  def pf_config
    path = File.join(@home, 'configs', 'darwin-pf.yaml')
    settings = YAML.safe_load(File.read(path))
    raise ArgumentError, 'darwin-pf.yaml must be a mapping' unless settings.is_a?(Hash)

    settings
  end

  def pf_port(value)
    port = Integer(value)
    raise ArgumentError, 'PF ports must be between 1 and 65535' unless (1..65_535).cover?(port)

    port
  end

  def redir_port
    pf_port(pf_config.fetch('redir-port', 7892))
  end

  def pf_ipv4(value)
    pf_address(value, :ipv4)
  end

  def pf_address(value, family)
    address = IPAddr.new(value)
    unless address.public_send("#{family}?") && address.prefix.positive?
      raise ArgumentError, "Specify a scoped #{family} address or CIDR: #{value}"
    end

    "#{address}/#{address.prefix}"
  end

  def pf_interface(name)
    names = Socket.getifaddrs.map(&:name)
    raise ArgumentError, "Invalid PF interface #{name.inspect}" unless name.to_s.match?(/\A[a-z][a-z0-9]*\d\z/) && names.include?(name) && name != 'lo0'

    name
  end

  def pf_service(settings, family = :ipv4)
    targets = Array(settings['targets']).map { |value| pf_address(value, family) }.uniq
    ports = Array(settings.fetch('ports', [80, 443])).map { |value| pf_port(value) }.uniq
    raise ArgumentError, "Declare at least one #{family} PF target and port" if targets.empty? || ports.empty?

    "{ #{targets.join(', ')} } port { #{ports.join(', ')} }"
  end

  def pf_selectors(settings, family = :ipv4)
    scope = settings.fetch('scope', 'local')
    raise ArgumentError, 'Use PF scope local, lan or both' unless %w[local lan both].include?(scope)

    selectors = []
    if scope != 'lan'
      default_uid = instance&.fetch('local-uid', nil) || ENV.fetch('SUDO_UID', '0')
      uid = Integer(settings.fetch('local-uid', default_uid))
      raise ArgumentError, 'Set local-uid to the non-root UID whose traffic should be captured' unless (1..4_294_967_294).cover?(uid)

      source = settings['local-source'] ? pf_address(settings['local-source'], family) : 'any'
      route = family == :ipv6 ? `/sbin/route -n get -inet6 default 2>/dev/null` : `/sbin/route -n get default 2>/dev/null`
      egress = settings['egress'] || route[/interface:\s+(\w+)/, 1]
      selectors << {'direction' => 'out', 'interface' => pf_interface(egress), 'source' => source, 'uid' => uid}
    end
    if scope != 'local'
      selectors << {'direction' => 'in', 'interface' => pf_interface(settings['lan-interface']), 'source' => pf_address(settings['lan-source'], family)}
    end
    selectors
  end

  def ipv6_redir?
    pf_config.key?('redir-ipv6')
  end

  def tcp6_plan(effective, settings = pf_config)
    ipv6 = settings['redir-ipv6']
    raise ArgumentError, 'redir-ipv6 must be a mapping' unless ipv6.is_a?(Hash)

    ipv6 = { 'scope' => settings.fetch('scope', 'local') }.merge(ipv6)
    targets = Array(ipv6['targets']).map { |value| pf_address(value, :ipv6) }.uniq
    ports = Array(ipv6.fetch('ports', [80, 443])).map { |port| pf_port(port) }.uniq
    raise ArgumentError, 'Declare IPv6 targets and ports for redir-ipv6' if targets.empty? || ports.empty?

    addresses = Socket.getifaddrs.select { |interface| interface.addr&.ipv6? }.reject { |interface| interface.addr.ipv6_linklocal? }
    selectors = pf_selectors(ipv6, :ipv6)
    selectors.each do |selector|
      source = selector['source']
      selector['clients'] = source == 'any' ? addresses.map { |item| "#{item.addr.ip_address}/128" }.uniq : [source]
      selector['listen'] = selector['direction'] == 'in' ? ipv6_lan_listener(ipv6, selector['interface'], addresses) : '::1'
    end
    ipv4_rules = Array(settings['targets']).empty? ? '' : pf_rules(nil, settings)
    socks_plan(effective, 'IPv6 Redir').merge('ipv4-rules' => ipv4_rules, 'targets' => targets,
                                              'ports' => ports, 'selectors' => selectors)
  end

  def ipv6_lan_listener(settings, interface, addresses)
    choices = addresses.select { |item| item.name == interface }.map { |item| item.addr.ip_address }
    address = settings['lan-listen-address'] || (choices.first if choices.length == 1)
    raise ArgumentError, 'Set lan-listen-address to an IPv6 address on lan-interface' unless address && choices.include?(address)

    address
  end

  def pf_rules(tunnel = nil, settings = pf_config, selectors = pf_selectors(settings))
    service = pf_service(settings)
    listener = "127.0.0.1 port #{pf_port(settings.fetch('redir-port', 7892))}"
    rdr = []
    routing = []
    selectors.each do |selector|
      source, egress, uid = selector.values_at('source', 'interface', 'uid')
      unless uid
        rdr << "rdr pass on #{egress} inet proto tcp from #{source} to #{service} -> #{listener}"
        next
      end

      rdr << "rdr pass on lo0 inet proto tcp from #{source} to #{service} -> #{listener}"
      routing << "pass out quick on #{egress} route-to (lo0 127.0.0.1) inet proto tcp from #{source} to #{service} user #{uid} no state"
    end
    routing.concat(tunnel_udp_rules(tunnel, selectors, service, :ipv4)) if tunnel
    (rdr + routing).join("\n") + "\n"
  end

  def tunnel_udp_rules(tunnel, selectors, service, family)
    address = Socket.getifaddrs.find do |interface|
      interface.name == tunnel && interface.addr&.public_send("#{family}?") && !interface.addr.ipv6_linklocal?
    end
    raise "Missing #{family} address on #{tunnel}" unless address

    pf_family = family == :ipv6 ? 'inet6' : 'inet'
    selectors.map do |selector|
      direction, device, source, uid = selector.values_at('direction', 'interface', 'source', 'uid')
      identity = uid ? " user #{uid}" : ''
      "pass #{direction} quick on #{device} route-to (#{tunnel} #{address.addr.ip_address}) #{pf_family} " \
        "proto udp from #{source} to #{service}#{identity} no state"
    end
  end

  def tproxy_plan(effective)
    settings = pf_config
    tcp6 = tcp6_plan(effective, settings) if settings.key?('redir-ipv6')
    families = {}
    ipv4_rules = ''
    if !tcp6 || !Array(settings['targets']).empty?
      selectors = pf_selectors(settings)
      families['4'] = tproxy_ipv4(settings, selectors)
      ipv4_rules = pf_rules(nil, settings, selectors)
    end
    families['6'] = tproxy_ipv6(settings.fetch('redir-ipv6'), tcp6) if tcp6
    socks_plan(effective, 'Tproxy').merge('ipv4-rules' => ipv4_rules, 'tcp6' => tcp6, 'families' => families)
  end

  def tproxy_ipv4(settings, selectors)
    targets = Array(settings['targets']).map { |address| pf_ipv4(address) }.uniq
    ports = Array(settings.fetch('ports', [80, 443])).map { |port| pf_port(port) }.uniq
    subnet = IPAddr.new(settings.fetch('udp-link-subnet', '198.19.247.0/30'))
    listener_alias = IPAddr.new(settings.fetch('udp-listen-address', '198.19.246.1'))
    unless subnet.ipv4? && subnet.prefix == 30 && listener_alias.ipv4? && listener_alias.prefix == 32 && !subnet.include?(listener_alias)
      raise ArgumentError, 'Tproxy needs an IPv4 /30 link and a separate /32 listener address'
    end
    if targets.any? { |target| IPAddr.new(target).include?(listener_alias) || IPAddr.new(target).include?(subnet) || subnet.include?(IPAddr.new(target)) }
      raise ArgumentError, 'Tproxy targets must exclude its own link and listener address'
    end
    clients = selectors.flat_map do |selector|
      if selector['source'] == 'any'
        Socket.getifaddrs.map(&:addr).compact.select(&:ipv4?).map { |address| "#{address.ip_address}/32" }
      else
        [selector['source']]
      end
    end.uniq
    raise ArgumentError, 'Tproxy requires at least one IPv4 client address' if clients.empty?

    { 'selectors' => selectors, 'clients' => clients, 'targets' => targets, 'ports' => ports,
      'subnet' => "#{subnet}/30", 'alias' => listener_alias.to_s, 'slots' => udp_slots(settings) }
  end

  def tproxy_ipv6(settings, tcp6)
    lan = tcp6['selectors'].find { |selector| selector['direction'] == 'in' }
    intake = IPAddr.new(settings.fetch('udp-link-address', 'fd53:6865:6c6c:246::1'))
    listener = lan ? IPAddr.new(lan['listen']) : intake
    unless intake.ipv6? && intake.prefix == 128 && (intake.to_i >> 121) == 126
      raise ArgumentError, 'IPv6 Tproxy needs a unique local /128 udp-link-address'
    end
    if tcp6['targets'].any? { |target| IPAddr.new(target).include?(listener) || IPAddr.new(target).include?(intake) }
      raise ArgumentError, 'IPv6 Tproxy targets must exclude its own link and listener addresses'
    end
    clients = tcp6['selectors'].flat_map { |selector| selector['clients'] }.uniq
    raise ArgumentError, 'Tproxy requires at least one IPv6 client address' if clients.empty?

    tcp6.slice('selectors', 'targets', 'ports').merge('clients' => clients, 'alias' => listener.to_s, 'link-address' => intake.to_s,
                                                      'slots' => udp_slots(settings))
  end

  def udp_slots(settings)
    slots = Integer(settings.fetch('udp-listeners', 128))
    raise ArgumentError, 'udp-listeners must be between 1 and 512' unless (1..512).cover?(slots)

    slots
  end

  def socks_plan(effective, label)
    config = YAML.safe_load(effective, aliases: true)
    proxy_port = Integer(config.fetch('mixed-port', 0))
    proxy_port = Integer(config.fetch('socks-port', 0)) if proxy_port.zero?
    raise ArgumentError, "#{label} requires a loopback mixed or SOCKS port" if proxy_port.zero?

    credentials = Array(config['authentication']).map { |item| item.to_s.split(':', 2) }.find { |pair| pair.size == 2 }
    { 'proxy-port' => proxy_port, 'credentials' => credentials }
  end

  def mount_pf(session)
    tcp6_plan = File.join(File.dirname(session['config']), 'tcp6-plan.json')
    if File.file?(tcp6_plan)
      if session['tun-device']
        settings = pf_config
        plan = JSON.parse(File.read(tcp6_plan))
        tunnel = session.fetch('tun-device')
        plan['ipv4-rules'] = pf_rules(tunnel, settings) unless plan['ipv4-rules'].empty?
        plan['udp-rules'] = tunnel_udp_rules(tunnel, plan['selectors'], pf_service(plan, :ipv6), :ipv6)
        atomic_write(tcp6_plan, JSON.generate(plan))
      end
      return IO.popen(['/usr/bin/python3', '-B', File.join(__dir__, 'darwin_tcp.py'), pf_mount_binary,
                       tcp6_plan, session['pid'].to_s, session['config']], 'r+')
    end
    if session['mode'] == 'tproxy'
      bridge = File.join(@home, 'bin', 'feth-qemu')
      raise "Build the Tproxy Ethernet helper at #{bridge}" unless File.executable?(bridge)

      plan = File.join(File.dirname(session['config']), 'udp-plan.json')
      return IO.popen(['/usr/bin/python3', '-B', File.join(__dir__, 'darwin_tproxy.py'), pf_mount_binary,
                       bridge, plan, session['pid'].to_s, session['config']], 'r+')
    end
    rules = File.join(File.dirname(session['config']), 'redir.pf')
    atomic_write(rules, pf_rules(session['tun-device']))
    pf_worker(rules, '--owned-core', session['pid'].to_s, session['config'])
  end

  def pf_worker(rules, *options)
    IO.popen(['/usr/bin/python3', '-B', File.join(__dir__, 'darwin_pf.py'), *options, pf_mount_binary, rules, '0', '/bin/cat'], 'r+')
  end

  def pf_mount_binary
    binary = File.join(@home, 'bin', 'pf_mount')
    raise "Build the PF mount helper at #{binary} before starting a PF mode" unless File.executable?(binary)
    binary
  end

  def bypass_config
    settings = pf_config['bypass']
    raise ArgumentError, 'Set bypass in configs/darwin-pf.yaml' unless settings.is_a?(Hash)

    ingress = pf_interface(settings['lan-interface'])
    egress = pf_interface(settings['egress'])
    hop = IPAddr.new(settings.fetch('next-hop'))
    ipv6 = hop.ipv6?
    family = ipv6 ? :ipv6 : :ipv4
    pf_family = ipv6 ? 'inet6' : 'inet'
    address, prefix = pf_address(settings['next-hop'], family).split('/')
    scoped = ipv6 && hop.link_local? ? "#{address}%#{egress}" : address
    local_addresses = Socket.getifaddrs.map(&:addr).compact
    if prefix.to_i != (ipv6 ? 128 : 32) ||
        local_addresses.any? { |entry| entry.ip? && entry.ip_address.split('%').first == address }
      raise ArgumentError, 'Set next-hop to another host on the bypass link'
    end
    route, result = Open3.capture2('/sbin/route', '-n', 'get', "-#{pf_family}", scoped, err: File::NULL)
    if !result.success? || route[/interface:\s+(\w+)/, 1] != egress || route[/flags: ([^\n]+)/, 1].to_s.include?('GATEWAY')
      raise ArgumentError, 'The bypass next hop must be reachable directly on egress'
    end
    protos = { 'tcp' => 'tcp', 'tcp+udp' => '{ tcp udp }' }[settings.fetch('protocol', 'tcp')]
    raise ArgumentError, 'Bypass protocol must be tcp or tcp+udp' unless protos

    health = settings.fetch('health-check', 'off')
    raise ArgumentError, 'Bypass health-check must be icmp or off' unless %w[icmp off].include?(health)

    source = pf_address(settings['lan-source'], family)
    service = pf_service(settings, family)
    rules = []
    if IPAddr.new(source).include?(address)
      rules << "pass in quick on #{ingress} #{pf_family} proto #{protos} from #{address} to #{service} no state"
    end
    rules << "pass in quick on #{ingress} route-to (#{egress} #{address}) #{pf_family} proto #{protos} from #{source} to #{service} no state"
    [rules.join("\n") + "\n", scoped, health == 'icmp', ipv6]
  end

  def preview_pf(mode)
    case mode
    when nil, 'redir'
      puts pf_rules unless ipv6_redir? && Array(pf_config['targets']).empty?
      puts '# IPv6 Redir listener ports are assigned when its relay starts.' if ipv6_redir?
    when 'bypass' then puts bypass_config.first
    else raise ArgumentError, 'Use pf-rules redir or pf-rules bypass'
    end
  end

  def check_mode(mode, source)
    return prepare_and_check(mode, source) unless mode == 'bypass'
    raise ArgumentError, 'Bypass uses configs/darwin-pf.yaml' if source

    Dir.mktmpdir('check-', @runtime) do |directory|
      rules = File.join(directory, 'forward.pf')
      atomic_write(rules, bypass_config.first)
      raise 'PF validation failed' unless system('/sbin/pfctl', '-n', '-a', 'shellcrash-pf-lab', '-f', rules)
    end
  end

  def bypass_reachable?(address)
    return system('/sbin/ping', '-n', '-c', '1', '-W', '500', address, out: File::NULL, err: File::NULL) unless address.include?(':')

    pid = Process.spawn('/sbin/ping6', '-n', '-c', '1', '-o', address, out: File::NULL, err: File::NULL)
    deadline = Process.clock_gettime(Process::CLOCK_MONOTONIC) + 0.5
    loop do
      result = Process.waitpid2(pid, Process::WNOHANG)
      return result.last.success? if result
      return false if Process.clock_gettime(Process::CLOCK_MONOTONIC) >= deadline

      sleep 0.05
    end
  ensure
    stop_child(pid) if pid
  end

  def launch_bypass(source)
    raise ArgumentError, 'Bypass uses configs/darwin-pf.yaml' if source
    raise 'Bypass requires root' unless Process.euid.zero?
    content, next_hop, health, ipv6 = bypass_config
    forwarding = ipv6 ? 'net.inet6.ip6.forwarding' : 'net.inet.ip.forwarding'
    raise "Enable #{forwarding} before running bypass" unless `/usr/sbin/sysctl -n #{forwarding}`.strip == '1'
    raise "Bypass next hop #{next_hop} did not answer ICMP" if health && !bypass_reachable?(next_hop)

    interrupted = false
    signals = %w[INT TERM HUP].map { |name| [name, Signal.trap(name) { interrupted = true }] }
    directory = worker = session = nil
    begin
      locked do
        raise 'A ShellCrash instance is already running' if running_session

        directory = Dir.mktmpdir('bypass-', @runtime)
        rules = File.join(directory, 'forward.pf')
        atomic_write(rules, content)
        worker = pf_worker(rules)
        wait_for_pf(worker) { interrupted }
        session = { 'pid' => worker.pid, 'mode' => 'bypass', 'config' => rules, 'next-hop' => next_hop,
                    'supervisor' => Process.pid, 'supervisor-start' => process_start(Process.pid) }
        atomic_write(@session_file, JSON.generate(session))
        puts "PF bypass running via #{next_hop}"
      end
      misses = 0
      check_at = Process.clock_gettime(Process::CLOCK_MONOTONIC) + 1
      until interrupted
        raise 'PF supervisor exited' if IO.select([worker], nil, nil, 0.1) && worker.eof?

        now = Process.clock_gettime(Process::CLOCK_MONOTONIC)
        next unless health && now >= check_at

        misses = bypass_reachable?(next_hop) ? 0 : misses + 1
        raise "Bypass next hop #{next_hop} stopped answering ICMP. Releasing PF rules." if misses >= 3

        check_at = Process.clock_gettime(Process::CLOCK_MONOTONIC) + 1
      end
    ensure
      begin
        release_pf(worker) if worker
      ensure
        signals.each { |name, handler| Signal.trap(name, handler) }
        locked { remove_session(session) } if session
        FileUtils.remove_entry_secure(directory) if directory && File.directory?(directory)
      end
    end
  end

  def interfaces
    `/sbin/ifconfig -l`.split.grep(/\Autun\d+\z/)
  end

  def core_ready?(pid, port)
    system('/usr/sbin/lsof', '-nP', '-a', '-p', pid.to_s, "-iTCP:#{port}", '-sTCP:LISTEN', out: File::NULL, err: File::NULL)
  end

  def read_session
    JSON.parse(File.read(@session_file)) if File.file?(@session_file)
  end

  def running_session
    session = read_session
    return unless session

    output, = Open3.capture2('/bin/ps', '-ww', '-p', session['pid'].to_s, '-o', 'command=')
    owned = if session['mode'] == 'bypass'
              output.include?(File.join(__dir__, 'darwin_pf.py'))
            else
              output.start_with?("#{@bin} ")
            end
    return session if owned && output.include?(session['config'])

    remove_session(session)
    nil
  end

  def remove_session(session)
    path = File.dirname(session['config'])
    if File.dirname(path) == @runtime && File.basename(path).start_with?('mihomo-', 'bypass-') && File.directory?(path)
      FileUtils.remove_entry_secure(path)
    end
    File.unlink(@session_file) if read_session == session
  end

  def status
    puts "ShellCrash (#{instance.fetch('scope')}): #{@home}" if instance
    if system_reader?
      return puts("Use sudo #{Shellwords.escape(instance.fetch('command'))} -s status to inspect system processes.")
    end
    session = running_session
    if session && session['mode'] == 'bypass'
      puts "PF bypass running via #{session['next-hop']}"
    elsif session
      puts "Mihomo #{session['mode']} running (PID #{session['pid']})#{port_summary(session)}"
    else
      puts 'Mihomo stopped'
    end
  end

  def port_summary(session)
    ports = session['ports'] || Array(session['port'])
    ports.empty? ? '' : ", loopback ports #{ports.join(', ')}"
  end

  def restart(args)
    session = running_session
    selected = args.empty? && session && !instance ? session['mode'] : mode(args)
    raise "Use run #{selected} in the foreground for the PF supervisor" if FOREGROUND_MODES.include?(selected)
    source = args.shift || (session && session['source'])
    stop
    start(selected, source, false)
  end

  def stop
    session = running_session
    return puts('Mihomo stopped') unless session

    service = session['mode'] == 'bypass' ? 'PF bypass' : 'Mihomo'

    supervisor = session['supervisor']
    if supervisor && session['supervisor-start'] == process_start(supervisor)
      signal(supervisor, 'TERM')
    else
      signal(session['pid'], 'TERM')
    end
    50.times do
      return puts("#{service} stopped") unless running_session

      sleep 0.1
    end
    raise "#{service} did not stop after SIGTERM"
  end

  def process_start(pid)
    value, status = Open3.capture2('/bin/ps', '-p', pid.to_s, '-o', 'lstart=')
    status.success? ? value.strip : nil
  end

  def signal(pid, name)
    Process.kill(name, pid)
  rescue Errno::ESRCH
    nil
  end
end

begin
  exit DarwinShellCrash.new.call(ARGV)
rescue ArgumentError, RuntimeError, SystemCallError, OptionParser::ParseError, Psych::Exception, Zlib::Error => error
  warn "ShellCrash: #{error.message}"
  exit 1
end
