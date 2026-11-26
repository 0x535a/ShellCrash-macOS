# Copyright (C) Juewuy

require 'fileutils'
require 'tmpdir'
require 'uri'

module DarwinDistribution
  FILES = %w[darwin.rb darwin_distribution.rb darwin_launchd.rb darwin_pf.py darwin_udp.py
             darwin_tcp.py darwin_tproxy.py menu.sh start.sh].freeze

  def self.download(url, path, protocols: '=https', timeout: 900)
    unless system('/usr/bin/curl', '-q', '--fail', '--silent', '--show-error', '--location',
                  '--proto', protocols, '--proto-redir', protocols, '--connect-timeout', '15',
                  '--max-time', timeout.to_s, '--output', path, '--', url)
      raise "Download failed for #{File.basename(path)}"
    end
  end

  def self.bootstrap(source, args)
    url = URI.parse(source.to_s)
    unless url.is_a?(URI::HTTPS) && url.host && !url.userinfo && !url.query && !url.fragment
      raise ArgumentError, 'Set url to the HTTPS root of a ShellCrash distribution'
    end
    root = url.to_s.sub(%r{/+\z}, '')
    Dir.mktmpdir('shellcrash-darwin-install-') do |directory|
      FILES.each do |file|
        path = File.join(directory, file)
        if file == 'darwin_distribution.rb'
          FileUtils.cp(__FILE__, path)
        else
          download("#{root}/scripts/#{file}", path, timeout: 60)
        end
      end
      system('/usr/bin/ruby', File.join(directory, 'darwin.rb'), 'install', *args)
      $?.exitstatus || 1
    end
  end
end

if $PROGRAM_NAME == __FILE__
  begin
    exit DarwinDistribution.bootstrap(ARGV.shift, ARGV)
  rescue ArgumentError, URI::InvalidURIError, RuntimeError, SystemCallError => error
    warn "ShellCrash: #{error.message}"
    exit 1
  end
end
