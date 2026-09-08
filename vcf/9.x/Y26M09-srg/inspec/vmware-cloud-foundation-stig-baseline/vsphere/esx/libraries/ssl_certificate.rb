#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.
#
# InSpec custom resource for SSL Certificates handling
# Author: Alex Pop
# Source from https://github.com/alexpop/ssl-certificate-profile

require 'uri'
require 'openssl'
require 'net/https'

# Custom resource based on the InSpec resource DSL
class SslCertificate < Inspec.resource(1)
  name 'ssl_certificate'

  desc "
    The `ssl_certificate` allows to test SSL Certificate properties like:
    days before expire, key size, hash algorithm, trust, etc
  "

  example "
    # Use defaults: port: 443 and hostname of the target
    describe ssl_certificate do
      it { should exist }
      its('signature_algorithm' { should cmp 'sha256WithRSAEncryption' }
    end

    # Be explicit with the targeted host and port
    describe ssl_certificate(host: 'github.com', port: 443) do
      it { should exist }
      it { should be_trusted }
      its('ssl_error') { should eq nil }
      its('signature_algorithm') { should eq 'sha256WithRSAEncryption' }
      its('hash_algorithm') { should cmp /SHA(256|384|512)/ }
      its('issuer_organization') { should match /^(Amazon|Let's Encrypt)/ }
      its('issuer_country') { should eq 'GB' }
      its('issuer_locality') { should eq 'Salford' }
      its('issuer_state') { should eq 'Greater Manchester' }
      its('issuer_organizational_unit') { should eq 'Server CA 1B' }
      its('issuer_common_name') { should eq 'COMODO RSA Domain Validation Secure Server CA' }
      its('expiration_days') { should be >= 30 }
      its('expiration') { should be > SOME_DATE }
    end
  "

  attr_reader :ssl_error

  def initialize(opts = {})
    case opts.class.to_s
    when 'NilClass'
      @port = 443
    when 'Hash'
      if opts[:path]
        @path = opts[:path]
      else
        @host = opts[:host]
        @port = opts[:port] || 443
        @timeout = opts[:timeout] if opts[:timeout]
      end
    else
      skip_resource "Unsupported parameter #{opts.inspect}. Must be a Hash, for example: ssl_certificate(host: 'github.com', port: 443)"
    end
  end

  # Called by: it { should exist }
  def exists?
    cert.class == OpenSSL::X509::Certificate
  end

  # Called by: it { should be_trusted }
  def trusted?
    ssl_error.nil?
  end

  # Called by: its('signature_algorithm') { should eq 'something' }
  def signature_algorithm
    cert.signature_algorithm
  end

  # Will return the full issuer string, for example:
  # /C=GB/ST=Greater Manchester/L=Salford/O=COMODO CA Limited/CN=COMODO RSA Domain Validation Secure Server CA
  def issuer
    cert.issuer.to_s
  end

  # The issuer_* methods below extract a specific attribute (Organization) from the full issuer string
  def issuer_country
    issuer_attribute('C')
  end

  def issuer_state
    issuer_attribute('ST') || issuer_attribute('S')
  end

  def issuer_locality
    issuer_attribute('L')
  end

  def issuer_organization
    issuer_attribute('O')
  end

  def issuer_common_name
    issuer_attribute('CN')
  end

  def issuer_organizational_unit
    issuer_attribute('OU')
  end

  def subject
    cert.subject.to_s
  end

  def hash_algorithm
    return cert.signature_algorithm.gsub(/.*(sha)-?(\d+).*/i, '\1\2').upcase if defined?(cert.signature_algorithm)
  end

  def expiration_days
    ((cert.not_after - Time.now) / 86_400).to_i
  end

  def expiration
    cert.not_after
  end

  def to_s
    return @path if @path

    p = (@port == 443 ? '' : ":#{@port}")
    "ssl_certificate for '#{@host}#{p}'"
  end

  private

  def issuer_attribute(attr)
    issuer[%r{/#{attr}=([^/]+)}, 1]
  end

  # Return the ssl object if there's one, if not instanciate it
  # Helps by not doing it in initialize to keep `inspec check` runs quick
  def cert
    return @cert_obj unless @cert_obj.nil?
    if @path
      # read the file from the target(local or remote node)
      cert_file = inspec.file(@path)
      return skip_resource "File missing at path: #{@path}" unless cert_file.exist?
      @cert_obj = OpenSSL::X509::Certificate.new(cert_file.content)
    else
      @host = get_hostname
      if @host.nil?
        return skip_resource "Cannot determine hostname to check for inspec.backend(#{inspec.backend.class.to_s}). Please specify a :host parameter"
      end
      @cert_obj = get_cert(verify: true)
    end
    @cert_obj
  end

  # Retrieve an OpenSSL::X509::Certificate via TCP
  def get_cert(verify: true)
    begin
      @http = Net::HTTP.new(@host, @port)
      @http.use_ssl = true
      @http.verify_mode = OpenSSL::SSL::VERIFY_NONE unless verify
      @http.open_timeout = @timeout if @timeout
      @http.start do |h|
        return h.peer_cert
      end
    rescue StandardError => e
      if verify == true
        @ssl_error = e.message.gsub(/"/, "'")
        # Trying one more time, this time not verifying the SSL Certificate
        get_cert(verify: false)
      else
        # Mark test as skipped if we can't get an SSL certificate
        skip_resource "Cannot connect to #{@host}:#{@port}, #{e.message}"
      end
    end
  end

  # Best effort to retrieve the hostname of the target
  def get_hostname
    return @host if @host
    # FIXME: This can be refactored once inspec 1.0 has a stable release and this profile depends on it. see the ssl.rb core resource
    hostname = inspec.backend.instance_variable_get(:@hostname)
    if hostname.nil? && inspec.backend.class.to_s == 'Train::Transports::WinRM::Connection'
      hostname = URI.parse(inspec.backend.instance_variable_get(:@options)[:endpoint]).hostname
    end
    if hostname.nil? && inspec.backend.class.to_s == 'Train::Transports::Local::Connection'
      hostname = 'localhost'
    end
    hostname
  end
end
