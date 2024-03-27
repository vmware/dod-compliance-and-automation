control 'CFNG-5X-000003' do
  title 'The SDDC Manager NGINX service must be configured with FIPS 140-2 compliant ciphers for HTTPS connections.'
  desc  "
    Encryption of data-in-flight is an essential element of protecting information confidentiality.  If a web server uses weak or outdated encryption algorithms, then the server's communications can potentially be compromised.

    The US Federal Information Processing Standards (FIPS) publication 140-2, Security Requirements for Cryptographic Modules (FIPS 140-2) identifies eleven areas for a cryptographic module used inside a security system that protects information.  FIPS 140-2 approved ciphers provide the maximum level of encryption possible for a private web server.
  "
  desc  'rationale', ''
  desc  'check', "
    At the command line, run the following command:

    # nginx -T 2>&1 | sed -n '/\\sserver\\s{/{:a;N;/.*location/!ba;/.*listen.*ssl/p}' | grep ssl_ciphers

    Example result:

    ssl_ciphers 'ECDHE-ECDSA-AES256-GCM-SHA384:ECDHE-RSA-AES256-GCM-SHA384:ECDHE-ECDSA-AES128-GCM-SHA256:ECDHE-RSA-AES128-GCM-SHA256:TLS_AES_128_GCM_SHA256:TLS_AES_128_CCM_8_SHA256:TLS_AES_128_CCM_SHA256:TLS_AES_256_GCM_SHA384';

    If the output matches the ciphers in the example result or a subset thereof, this is not a finding.

    If the ciphers in the output contain any ciphers not listed in the example result, this is a finding.
  "
  desc 'fix', "
    Navigate to and open:

    The nginx.conf (/etc/nginx/nginx.conf by default) file.

    Add the following line in the server context for each server that is terminating ssl:

    ssl_ciphers 'ECDHE-ECDSA-AES256-GCM-SHA384:ECDHE-RSA-AES256-GCM-SHA384:ECDHE-ECDSA-AES128-GCM-SHA256:ECDHE-RSA-AES128-GCM-SHA256:TLS_AES_128_GCM_SHA256:TLS_AES_128_CCM_8_SHA256:TLS_AES_128_CCM_SHA256:TLS_AES_256_GCM_SHA384';

    At the command line, run the following command:

    # nginx -s reload
  "
  impact 0.5
  tag severity: 'medium'
  tag gtitle: 'SRG-APP-000014-WSR-000006'
  tag gid: 'V-CFNG-5X-000003'
  tag rid: 'SV-CFNG-5X-000003'
  tag stig_id: 'CFNG-5X-000003'
  tag cci: ['CCI-000068']
  tag nist: ['AC-17 (2)']

  ciphers = input('nginx_ssl_ciphers')
  http_ciphers = nginx_conf_custom(input('nginx_conf_path')).params['http'][0]['ssl_ciphers']
  servers = nginx_conf_custom(input('nginx_conf_path')).servers

  # Check server blocks
  if http_ciphers
    httpsciphers = http_ciphers.flatten.first.split(':')
    # Check setting in HTTP block
    httpsciphers.each do |httpcipher|
      describe httpcipher do
        it { should be_in ciphers }
      end
    end
    servers.each do |server|
      next unless server.params['listen'].flatten.include?('ssl')
      server_ciphers = server.params['ssl_ciphers']
      if server_ciphers
        serverciphers = server_ciphers.flatten.first.split(':')
        serverciphers.each do |servercipher|
          describe "Checking server block: #{server.params['server_name']} its ssl_cipher #{servercipher} should be FIPS validated" do
            subject { servercipher }
            it { should be_in ciphers }
          end
        end
      else
        describe "Checking server block: #{server.params['server_name']}" do
          it 'its ssl_ciphers should not exist since they are defined at the http level' do
            expect(server.params['ssl_ciphers']).to be nil
          end
        end
      end
    end
  else
    servers.each do |server|
      next unless server.params['listen'].flatten.include?('ssl')
      server_ciphers = server.params['ssl_ciphers']
      if server_ciphers
        serverciphers = server_ciphers.flatten.first.split(':')
        serverciphers.each do |servercipher|
          describe "No HTTP context configuration detected. Checking server block: #{server.params['server_name']} its ssl_cipher #{servercipher} should be FIPS validated" do
            subject { servercipher }
            it { should be_in ciphers }
          end
        end
      else
        describe "No HTTP context configuration detected. Checking server block: #{server.params['server_name']}" do
          it 'its ssl_ciphers should exist since they are not defined at the http level' do
            expect(server.params['ssl_ciphers']).not_to be nil
          end
        end
      end
    end
  end
end
