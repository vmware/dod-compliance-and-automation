control 'CFNG-5X-000090' do
  title 'The SDDC Manager NGINX service must maintain the confidentiality of controlled information during transmission through the use of an approved TLS version.'
  desc  "
    Transport Layer Security (TLS) is a required transmission protocol for a web server hosting controlled information. The use of TLS provides confidentiality of data in transit between the web server and client. FIPS 140-2 approved TLS versions must be enabled and non-FIPS-approved SSL versions must be disabled.

    NIST SP 800-52 defines the approved TLS versions for government applications.
  "
  desc  'rationale', ''
  desc  'check', "
    At the command line, run the following command:

    # nginx -T 2>&1 | sed -n '/\\sserver\\s{/{:a;N;/.*location/!ba;/.*listen.*ssl/p}' | grep ssl_protocols

    Example result:

    ssl_protocols TLSv1.2 TLSv1.3;

    If \"ssl_protocols\" is not configured to \"TLSv1.2\", this is a finding.
  "
  desc 'fix', "
    Navigate to and open:

    The nginx.conf (/etc/nginx/nginx.conf by default) file.

    Add the following line in the http context for each server that is terminating ssl:

    ssl_protocols TLSv1.2 TLSv1.3;

    At the command line, run the following command:

    # nginx -s reload
  "
  impact 0.5
  tag severity: 'medium'
  tag gtitle: 'SRG-APP-000439-WSR-000156'
  tag satisfies: ['SRG-APP-000172-WSR-000104', 'SRG-APP-000439-WSR-000151', 'SRG-APP-000439-WSR-000152', 'SRG-APP-000441-WSR-000181', 'SRG-APP-000442-WSR-000182']
  tag gid: 'V-CFNG-5X-000090'
  tag rid: 'SV-CFNG-5X-000090'
  tag stig_id: 'CFNG-5X-000090'
  tag cci: ['CCI-000197', 'CCI-002418', 'CCI-002420', 'CCI-002422']
  tag nist: ['IA-5 (1) (c)', 'SC-8', 'SC-8 (2)']

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
