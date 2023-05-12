control 'CFNG-4X-000005' do
  title 'The SDDC Manager NGINX service must use cryptography to protect the integrity of remote sessions.'
  desc  'Data exchanged between the user and the web server can range from static display data to credentials used to log into the hosted application. Even when data appears to be static, the non-displayed logic in a web page may expose business logic or trusted system relationships. The integrity of all the data being exchanged between the user and web server must always be trusted. To protect the integrity and trust, encryption methods should be used to protect the complete communication session.'
  desc  'rationale', ''
  desc  'check', "
    At the command line, run the following command:

    # nginx -T 2>&1 | sed -n '/\\sserver\\s{/{:a;N;/.*location/!ba;/.*listen.*ssl/p}' | grep ssl_protocols

    ssl_protocols TLSv1.2;

    If the output does not match the expected result, this is a finding.
  "
  desc 'fix', "
    Navigate to and open:

    The nginx.conf (/etc/nginx/nginx.conf by default) file.

    Add the following line in the http context for each server that is terminating ssl:

    ssl_protocols TLSv1.2;

    At the command line, run the following command:

    # nginx -s reload
  "
  impact 0.5
  tag severity: 'medium'
  tag gtitle: 'SRG-APP-000015-WSR-000014'
  tag satisfies: ['SRG-APP-000172-WSR-000104', 'SRG-APP-000179-WSR-000111', 'SRG-APP-000439-WSR-000152', 'SRG-APP-000439-WSR-000156', 'SRG-APP-000439-WSR-000188', 'SRG-APP-000441-WSR-000181', 'SRG-APP-000442-WSR-000182']
  tag gid: 'V-CFNG-4X-000005'
  tag rid: 'SV-CFNG-4X-000005'
  tag stig_id: 'CFNG-4X-000005'
  tag cci: ['CCI-000197', 'CCI-000803', 'CCI-001453', 'CCI-002418', 'CCI-002420', 'CCI-002422']
  tag nist: ['AC-17 (2)', 'IA-5 (1) (c)', 'IA-7', 'SC-8', 'SC-8 (2)']

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
      next unless server.params['listen'].flatten.include?('ssl')
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
      next unless server.params['listen'].flatten.include?('ssl')
      describe "Checking server block: #{server.params['server_name']}" do
        it 'its ssl_protocols should be TLS1.2 or 1.3' do
          expect(server.params['ssl_protocols']).to be_in protocols
        end
      end
    end
  end
end
