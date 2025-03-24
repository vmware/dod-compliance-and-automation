control 'CFNG-5X-000091' do
  title 'The SDDC Manager NGINX service must be configured to prefer server ciphers over the clients.'
  desc  'During the initial setup of a Transport Layer Security (TLS) connection to the web server, the client sends a list of supported cipher suites in order of preference.  The web server will reply with the cipher suite it will use for communication from the client list.  If an attacker can intercept the submission of cipher suites to the web server and place, as the preferred cipher suite, a weak export suite, the encryption used for the session becomes easy for the attacker to break, often within minutes to hours.'
  desc  'rationale', ''
  desc  'check', "
    At the command line, run the following command:

    # nginx -T 2>&1 | sed -n '/\\sserver\\s{/{:a;N;/.*location/!ba;/.*listen.*ssl/p}' | grep ssl_prefer_server_ciphers

    Example result:

    ssl_prefer_server_ciphers on;

    If \"ssl_prefer_server_ciphers\" is not configured to \"on\", this is a finding.
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
  tag gtitle: 'SRG-APP-000439-WSR-000188'
  tag gid: 'V-CFNG-5X-000091'
  tag rid: 'SV-CFNG-5X-000091'
  tag stig_id: 'CFNG-5X-000091'
  tag cci: ['CCI-002418']
  tag nist: ['SC-8']

  # Check server blocks to ensure setting doesn't exist or is on
  servers = nginx_conf_custom(input('nginx_conf_path')).servers

  if !servers.empty?
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
  else
    describe 'No server contexts...skipping.' do
      skip 'No server contexts...skipping.'
    end
  end
end
