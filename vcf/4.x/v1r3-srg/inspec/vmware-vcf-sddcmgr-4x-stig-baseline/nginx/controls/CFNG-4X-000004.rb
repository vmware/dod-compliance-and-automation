control 'CFNG-4X-000004' do
  title 'The SDDC Manager NGINX service must be configured with FIPS 140-2 compliant ciphers for HTTPS connections and prefer server ciphers.'
  desc  "
    Encryption of data-in-flight is an essential element of protecting information confidentiality.  If a web server uses weak or outdated encryption algorithms, then the server's communications can potentially be compromised.

    The US Federal Information Processing Standards (FIPS) publication 140-2, Security Requirements for Cryptographic Modules (FIPS 140-2) identifies eleven areas for a cryptographic module used inside a security system that protects information.  FIPS 140-2 approved ciphers provide the maximum level of encryption possible for a private web server.
  "
  desc  'rationale', ''
  desc  'check', "
    At the command line, run the following command:

    # nginx -T 2>&1 | sed -n '/\\sserver\\s{/{:a;N;/.*location/!ba;/.*listen.*ssl/p}' | grep ssl_prefer_server_ciphers

    ssl_prefer_server_ciphers on;

    If the output does not match the expected result, this is a finding.
  "
  desc 'fix', "
    Navigate to and open:

    The nginx.conf (/etc/nginx/nginx.conf by default) file.

    Add the following line in the server context for each server that is terminating ssl:

    ssl_prefer_server_ciphers on;

    At the command line, run the following command:

    # nginx -s reload
  "
  impact 0.5
  tag severity: 'medium'
  tag gtitle: 'SRG-APP-000014-WSR-000006'
  tag satisfies: ['SRG-APP-000416-WSR-000118', 'SRG-APP-000439-WSR-000151']
  tag gid: nil
  tag rid: nil
  tag stig_id: 'CFNG-4X-000004'
  tag cci: ['CCI-000068', 'CCI-002450', 'CCI-002418']
  tag nist: ['AC-17 (2)', 'SC-13', 'SC-8']

  # Check server blocks to ensure setting doesn't exist or is on
  servers = nginx_conf_custom(input('nginx_conf_path')).servers

  servers.each do |server|
    next unless server.params['listen'].flatten.include?('ssl')
    describe.one do
      describe "Checking server block: #{server.params['server_name']}" do
        it 'its ssl_prefer_server_ciphers should be on' do
          expect(server.params['ssl_prefer_server_ciphers']).to include(['on'])
        end
      end
      describe "Checking server block: #{server.params['server_name']}" do
        it 'its ssl_prefer_server_ciphers should not exist' do
          expect(server.params['ssl_prefer_server_ciphers']).to be nil
        end
      end
    end
  end
end
