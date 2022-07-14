control 'NGNX-WB-000090' do
  title 'NGINX must maintain the confidentiality of controlled information during transmission through the use of an approved TLS version.'
  desc  "
    Transport Layer Security (TLS) is a required transmission protocol for a web server hosting controlled information. The use of TLS provides confidentiality of data in transit between the web server and client. FIPS 140-2 approved TLS versions must be enabled and non-FIPS-approved SSL versions must be disabled.

    NIST SP 800-52 defines the approved TLS versions for government applications.
  "
  desc  'rationale', ''
  desc  'check', "
    Verify TLS 1.2+ is enabled for each server block.

    View the running configuration by running the following command:

    # nginx -T

    Example configuration:

    server {
      ssl_protocols TLSv1.2;
    }

    If the ssl_protocol option is not configure to only support TLS 1.2 or 1.3, this is a finding.
  "
  desc 'fix', "
    Navigate to and open:

    The nginx.conf (/etc/nginx/nginx.conf by default or the included file where the server is defined) file.

    Add the ssl_protocols directive to the servers block, for example:

    ssl_protocols TLSv1.2;

    Reload the NGINX configuration by running the following command:

    # nginx -s reload
  "
  impact 0.5
  tag severity: 'medium'
  tag gtitle: 'SRG-APP-000439-WSR-000156'
  tag satisfies: ['SRG-APP-000439-WSR-000151', 'SRG-APP-000441-WSR-000181', 'SRG-APP-000442-WSR-000182']
  tag gid: nil
  tag rid: nil
  tag stig_id: 'NGNX-WB-000090'
  tag cci: ['CCI-002418', 'CCI-002418', 'CCI-002420', 'CCI-002422']
  tag nist: ['SC-8', 'SC-8', 'SC-8 (2)', 'SC-8 (2)']

  protocols = [['TLSv1.2'], ['TLSv1.3']]
  http_protocols = nginx_conf_custom(input('nginx_conf_path')).params['http'][0]['ssl_protocols']
  servers = nginx_conf_custom(input('nginx_conf_path')).servers

  # Check server blocks
  if http_protocols
    # Check setting in HTTP block
    describe http_protocols do
      it { should be_in protocols }
    end
    servers.each do |server|
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
    end
  else
    servers.each do |server|
      describe "Checking server block: #{server.params['server_name']}" do
        it 'its ssl_protocols should be TLS1.2 or 1.3' do
          expect(server.params['ssl_protocols']).to be_in protocols
        end
      end
    end
  end
end
