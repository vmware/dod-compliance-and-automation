control 'VCFO-9X-000090' do
  title 'The VMware Cloud Foundation Operations for Networks Platform NGINX server must maintain the confidentiality of controlled information during transmission through the use of an approved TLS version.'
  desc  "
    Transport Layer Security (TLS) is a required transmission protocol for a web server hosting controlled information. The use of TLS provides confidentiality of data in transit between the web server and client. FIPS 140-2 approved TLS versions must be enabled and nonFIPS-approved SSL versions must be disabled.

    NIST SP 800-52 defines the approved TLS versions for government applications.
  "
  desc  'rationale', ''
  desc  'check', "
    Verify TLS 1.2+ is enabled for each server context.

    View the running configuration by running the following command:

    # nginx -T 2>&1 | sed -n '/server\\s{/{:a;N;/.*location/!ba;/listen.*\\sssl/p}' | grep ssl_protocols

    Example configuration:

    server {
      ssl_protocols TLSv1.2 TLSv1.3;
    }

    If the \"ssl_protocol\" directive is not configured to only support TLS 1.2 or 1.3 in each SSL enabled server context, this is a finding.
  "
  desc 'fix', "
    Navigate to and open:

    The /etc/nginx/sites-available/vnera file.

    Add or update the \"ssl_protocols\" directive for the server context listening on port 443, for example:

    ssl_protocols TLSv1.2 TLSv1.3;

    Reload the NGINX configuration by running the following command:

    # nginx -s reload
  "
  impact 0.5
  tag severity: 'medium'
  tag gtitle: 'SRG-APP-000439-WSR-000156'
  tag satisfies: ['SRG-APP-000439-WSR-000151', 'SRG-APP-000441-WSR-000181', 'SRG-APP-000442-WSR-000182']
  tag gid: 'V-VCFO-9X-000090'
  tag rid: 'SV-VCFO-9X-000090'
  tag stig_id: 'VCFO-9X-000090'
  tag cci: ['CCI-002418', 'CCI-002420', 'CCI-002422']
  tag nist: ['SC-8', 'SC-8 (2)']

  protocols = ['TLSv1.2', 'TLSv1.3']
  http_protocols = nginx_conf_custom(input('nginx_conf_path')).params['http'][0]['ssl_protocols']
  servers = nginx_conf_custom(input('nginx_conf_path')).servers

  # Check server blocks
  if http_protocols
    httpsprotocols = http_protocols.flatten
    # Check setting in HTTP block
    httpsprotocols.each do |httpsprotocol|
      describe httpsprotocol do
        it { should be_in protocols }
      end
    end
    servers.each do |server|
      next unless server.params['listen'].flatten.include?('ssl')
      server_protocols = server.params['ssl_protocols']
      if server_protocols
        serverprotocols = server_protocols.flatten
        serverprotocols.each do |serverprotocol|
          describe "Checking server block: #{server.params['server_name']} its ssl_protocol #{serverprotocol}" do
            subject { serverprotocol }
            it { should be_in protocols }
          end
        end
      else
        describe "Checking server block: #{server.params['server_name']}" do
          it 'its ssl_protocol should not exist since they are defined at the http level' do
            expect(server.params['ssl_protocols']).to be nil
          end
        end
      end
    end
  else
    servers.each do |server|
      next unless server.params['listen'].flatten.include?('ssl')
      server_protocols = server.params['ssl_protocols']
      if server_protocols
        serverprotocols = server_protocols.flatten
        serverprotocols.each do |serverprotocol|
          describe "No HTTP context configuration detected. Checking server block: #{server.params['server_name']} its ssl_protocol #{serverprotocol}" do
            subject { serverprotocol }
            it { should be_in protocols }
          end
        end
      else
        describe "No HTTP context configuration detected. Checking server block: #{server.params['server_name']}" do
          it 'its ssl_protocol should not exist since they are defined at the http level' do
            expect(server.params['ssl_protocols']).not_to be nil
          end
        end
      end
    end
  end
end
