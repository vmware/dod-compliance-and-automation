control 'NGNX-WB-000091' do
  title 'NGINX must configure ciphers to protect the confidentiality and integrity of transmitted information.'
  desc  'During the initial setup of a Transport Layer Security (TLS) connection to the web server, the client sends a list of supported cipher suites in order of preference.  The web server will reply with the cipher suite it will use for communication from the client list.  If an attacker can intercept the submission of cipher suites to the web server and place, as the preferred cipher suite, a weak export suite, the encryption used for the session becomes easy for the attacker to break, often within minutes to hours.'
  desc  'rationale', ''
  desc  'check', "
    Verify the ssl_ciphers list in the http block.

    View the running configuration by running the following command:

    # nginx -T

    Example configuration:

    http {
      ssl_ciphers 'ECDHE-ECDSA-AES256-GCM-SHA384:ECDHE-RSA-AES256-GCM-SHA384:ECDHE-ECDSA-AES128-GCM-SHA256:ECDHE-RSA-AES128-GCM-SHA256';
    }

    If the \"ssl_ciphers\" directive is not configured as shown or not set to \"FIPS\", this is a finding.

    If the \"ssl_ciphers\" directive is configured in a server or location block and not configured as shown or not set to \"FIPS\", this is a finding.
  "
  desc 'fix', "
    Navigate to and open:

    The nginx.conf (/etc/nginx/nginx.conf by default) file.

    Add the ssl_ciphers option to the http block, for example:

    ssl_ciphers 'ECDHE-ECDSA-AES256-GCM-SHA384:ECDHE-RSA-AES256-GCM-SHA384:ECDHE-ECDSA-AES128-GCM-SHA256:ECDHE-RSA-AES128-GCM-SHA256';

    or

    ssl_ciphers 'FIPS';

    Reload the NGINX configuration by running the following command:

    # nginx -s reload

    Note: The first option is a subset of the FIPS list and compatible with TLS 1.2.
  "
  impact 0.5
  tag severity: 'medium'
  tag gtitle: 'SRG-APP-000439-WSR-000188'
  tag gid: 'V-NGNX-WB-000091'
  tag rid: 'SV-NGNX-WB-000091'
  tag stig_id: 'NGNX-WB-000091'
  tag cci: ['CCI-002418']
  tag nist: ['SC-8']

  ciphers = [[input('nginx_ssl_ciphers')], ['FIPS']]
  http_ciphers = nginx_conf_custom(input('nginx_conf_path')).params['http'][0]['ssl_ciphers']
  servers = nginx_conf_custom(input('nginx_conf_path')).servers

  # Check server blocks
  if !http_ciphers.nil?
    # Check setting in HTTP block
    describe http_ciphers do
      it { should be_in ciphers }
    end
    if !servers.empty?
      servers.each do |server|
        describe.one do
          describe "Checking server block: #{server.params['server_name']}" do
            it 'its ssl_ciphers should be TLS1.2 or 1.3' do
              expect(server.params['ssl_ciphers']).to be_in ciphers
            end
          end
          describe "Checking server block: #{server.params['server_name']}" do
            it 'its ssl_ciphers should not exist' do
              expect(server.params['ssl_ciphers']).to be nil
            end
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
      describe "Checking server block: #{server.params['server_name']}" do
        it "its ssl_ciphers should be in #{ciphers}" do
          expect(server.params['ssl_ciphers']).to be_in ciphers
        end
      end
    end
  else
    describe 'No server directives defined...' do
      skip 'No server directives defined...skipping...'
    end
  end
end
