control 'VCFO-9X-000098' do
  title 'The VMware Cloud Foundation Operations for Networks Platform NGINX server must prefer server ciphers over client ciphers when using SSL/TLS.'
  desc  'During the initial setup of a Transport Layer Security (TLS) connection to the web server, the client sends a list of supported cipher suites in order of preference.  The web server will reply with the cipher suite it will use for communication from the client list.  If an attacker can intercept the submission of cipher suites to the web server and place, as the preferred cipher suite, a weak export suite, the encryption used for the session becomes easy for the attacker to break, often within minutes to hours.'
  desc  'rationale', ''
  desc  'check', "
    Verify the NGINX is configured to prefer server TLS ciphers.

    View the running configuration by running the following command:

    # nginx -T 2>&1 | sed -n '/server\\s{/{:a;N;/.*location/!ba;/listen.*\\sssl/p}' | grep ssl_prefer_server_ciphers

    Example configuration:

    http {
       ssl_prefer_server_ciphers on;
    }

    If the \"ssl_prefer_server_ciphers\" directive is not configured in the http context or set to \"off\", this is a finding.

    If the \"ssl_prefer_server_ciphers\" directive is configured in a server context and set to \"off\", this is a finding.
  "
  desc 'fix', "
    Navigate to and open:

    The /etc/nginx/sites-available/vnera file.

    Add or update the \"ssl_prefer_server_ciphers\" directive for the server context listening on port 443, for example:

    ssl_prefer_server_ciphers on;

    Reload the NGINX configuration by running the following command:

    # nginx -s reload
  "
  impact 0.5
  tag severity: 'medium'
  tag gtitle: 'SRG-APP-000439-WSR-000188'
  tag gid: 'V-VCFO-9X-000098'
  tag rid: 'SV-VCFO-9X-000098'
  tag stig_id: 'VCFO-9X-000098'
  tag cci: ['CCI-002418']
  tag nist: ['SC-8']

  httpsslprefer = nginx_conf_custom(input('nginx_conf_path')).params['http'][0]['ssl_prefer_server_ciphers']
  servers = nginx_conf_custom(input('nginx_conf_path')).servers

  # Check HTTP context. If defined here it should be on. If not here it should be defined in every ssl enabled server context.
  if httpsslprefer
    describe "Detected 'ssl_prefer_server_ciphers' directive in http context" do
      subject { httpsslprefer }
      it { should cmp 'on' }
    end
    if !servers.empty?
      servers.each do |server|
        server_prefer = server.params['ssl_prefer_server_ciphers']
        next unless server.params['listen'].flatten.include?('ssl') && server_prefer
        describe.one do
          describe "Found ssl_prefer_server_ciphers defined in server context with listener: #{server.params['listen']}" do
            subject { server.params['ssl_prefer_server_ciphers'] }
            it { should cmp 'on' }
          end
          describe "ssl_prefer_server_ciphers not defined in server context with listener: #{server.params['listen']}" do
            subject { server.params['ssl_prefer_server_ciphers'] }
            it { should be nil }
          end
        end
      end
    else
      describe 'No server contexts...skipping.' do
        skip 'No server contexts...skipping.'
      end
    end
  # Check all SSL enabled server contexts.
  elsif !servers.empty?
    servers.each do |server|
      next unless server.params['listen'].flatten.include?('ssl')
      describe "Checking server block with listen directive: #{server.params['listen']}" do
        it 'its ssl_prefer_server_ciphers should be on' do
          expect(server.params['ssl_prefer_server_ciphers']).to include(['on'])
        end
      end
    end
  elsif servers.empty?
    describe 'No server contexts...skipping.' do
      skip 'No server contexts...skipping.'
    end
  end
end
