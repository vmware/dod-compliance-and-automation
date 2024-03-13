control 'VLMN-8X-000090' do
  title 'The VMware Aria Suite Lifecycle web service must maintain the confidentiality of controlled information during transmission through the use of an approved TLS version.'
  desc  "
    Transport Layer Security (TLS) is a required transmission protocol for a web server hosting controlled information. The use of TLS provides confidentiality of data in transit between the web server and client. FIPS 140-2 approved TLS versions must be enabled and non-FIPS-approved SSL versions must be disabled.

    NIST SP 800-52 defines the approved TLS versions for government applications.
  "
  desc  'rationale', ''
  desc  'check', "
    Verify TLS 1.2+ is enabled for each server block that is not a redirect to a secure port.

    View the running configuration by running the following command:

    # nginx -T

    Example configuration:

    server {
      ssl_protocols TLSv1.2;
    }

    If the ssl_protocol option is not configured to only support TLS 1.2 or 1.3, this is a finding.
  "
  desc 'fix', "
    Navigate to and open the nginx.conf file (/etc/nginx/nginx.conf by default or the included file where the server is defined).

    Add the ssl_protocols directive to each servers block that is not a redirect to a secure port , for example:

    ssl_protocols TLSv1.2;

    Reload the configuration by running the following command:

    # nginx -s reload
  "
  impact 0.5
  tag severity: 'medium'
  tag gtitle: 'SRG-APP-000439-WSR-000156'
  tag satisfies: %w(SRG-APP-000439-WSR-000151 SRG-APP-000439-WSR-000188 SRG-APP-000441-WSR-000181 SRG-APP-000442-WSR-000182)
  tag gid: 'V-VLMN-8X-000090'
  tag rid: 'SV-VLMN-8X-000090'
  tag stig_id: 'VLMN-8X-000090'
  tag cci: %w(CCI-002418 CCI-002420 CCI-002422)
  tag nist: ['SC-8', 'SC-8 (2)']

  protocols = [['TLSv1.2', 'TLSv1.3']]
  http_protocols = nginx_conf_custom(input('nginx_conf_path')).params['http'][0]['ssl_protocols']
  servers = nginx_conf_custom(input('nginx_conf_path')).servers

  # Check server blocks
  if !http_protocols.nil?
    # Check setting in HTTP block
    describe http_protocols do
      it { should be_in protocols }
    end
    if !servers.empty?
      describe.one do
        describe "Checking server block: #{server.params['server_name']}" do
          it 'its ssl_protocols should be TLS1.2 or 1.3' do
            expect(server.params['ssl_protocols']).to be_in protocols
          end
        end
        describe "Checking server block: #{server.params['server_name']}" do
          it 'its ssl_protocols should not exist' do
            expect(server.params['ssl_protocols']).to be nil
          end
        end
      end
    else
      describe 'No server directives defined...' do
        skip 'No server directives defined...skipping...'
      end
    end
  elsif !servers.empty?
    servers.each do |server|
      if server.params['listen'].include?(['80'])
        describe 'Port 80 should be a redirect to a secure port' do
          skip { 'Verify port 80 is a redirect to a secure port' }
        end
      else
        describe "Checking server block: #{server.params['server_name']}" do
          it 'its ssl_protocols should be TLS1.2 or 1.3' do
            expect(server.params['ssl_protocols']).to be_in protocols
          end
        end
      end
    end
  else
    describe 'No server directives defined...' do
      skip 'No server directives defined...skipping...'
    end
  end
end