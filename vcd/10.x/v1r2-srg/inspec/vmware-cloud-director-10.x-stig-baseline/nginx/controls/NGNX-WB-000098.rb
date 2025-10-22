control 'NGNX-WB-000098' do
  title 'NGINX must prefer service ciphers over client ciphers when using SSL/TLS.'
  desc  'During the initial setup of a Transport Layer Security (TLS) connection to the web server, the client sends a list of supported cipher suites in order of preference.  The web server will reply with the cipher suite it will use for communication from the client list.  If an attacker can intercept the submission of cipher suites to the web server and place, as the preferred cipher suite, a weak export suite, the encryption used for the session becomes easy for the attacker to break, often within minutes to hours.'
  desc  'rationale', ''
  desc  'check', "
    Verify the ssl_prefer_server_ciphers directive in the http block.

    View the running configuration by running the following command:

    # nginx -T

    Example configuration:

    http {
       ssl_prefer_server_ciphers on;
    }

    If the \"ssl_prefer_server_ciphers\" directive is not configured in the http block or set to off, this is a finding.

    If the \"ssl_prefer_server_ciphers\" directive is configured in a server block and set to off, this is a finding.
  "
  desc 'fix', "
    Navigate to and open:

    The nginx.conf (/etc/nginx/nginx.conf by default) file.

    Add the ssl_prefer_server_ciphers option to the http block, for example:

    ssl_prefer_server_ciphers on;

    Reload the NGINX configuration by running the following command:

    # nginx -s reload
  "
  impact 0.5
  tag severity: 'medium'
  tag gtitle: 'SRG-APP-000439-WSR-000188'
  tag gid: 'V-NGNX-WB-000098'
  tag rid: 'SV-NGNX-WB-000098'
  tag stig_id: 'NGNX-WB-000098'
  tag cci: ['CCI-002418']
  tag nist: ['SC-8']

  # Check for setting in HTTP block
  describe nginx_conf_custom(input('nginx_conf_path')).params['http'][0]['ssl_prefer_server_ciphers'] do
    it { should include ['on'] }
  end

  # Check server blocks to ensure setting doesn't exist or is on
  servers = nginx_conf_custom(input('nginx_conf_path')).servers

  servers.each do |server|
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
