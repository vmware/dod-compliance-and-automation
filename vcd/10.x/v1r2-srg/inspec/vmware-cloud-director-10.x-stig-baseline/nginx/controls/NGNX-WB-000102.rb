control 'NGNX-WB-000102' do
  title 'NGINX must disable SSL session tickets.'
  desc  "Perfect forward secrecy is an encryption mechanism that enables past session keys to not be compromised even if the server's private key is compromised. If an attacker recorded all traffic to a server and stored it and then obtained the private key without perfect forward secrecy, all communications would be compromised. With perfect forward secrecy, session keys are generated using Diffie-Hellman for every session a user initiates, which isolates session compromise to only that communication session. Allowing session resumption breaks perfect forward secrecy; this expands the surface area for an attacker to compromise past sessions and communications with a server if they are able to compromise the session."
  desc  'rationale', ''
  desc  'check', "
    If TLS 1.3 only is configured, this is NOT applicable.

    Verify that SSL session tickets are disabled.

    View the running configuration by running the following command:

    # nginx -T 2>&1 | grep \"ssl_session_tickets\"

    Example configuration:

    http {
      ssl_session_tickets off;
    }

    If the the \"ssl_session_tickets\" directive is not set to off in the http block, this is a finding.

    If the \"ssl_session_tickets\" directive is configured in a server or location block and set to on, this is a finding.
  "
  desc 'fix', "
    Navigate to and open:

    The nginx.conf (/etc/nginx/nginx.conf by default) file.

    Add the \"ssl_session_tickets\" directive to the http block, for example:

    ssl_session_tickets off;

    Remove any \"ssl_session_tickets\" from server and location blocks.

    Reload the NGINX configuration by running the following command:

    # nginx -s reload
  "
  impact 0.5
  tag severity: 'medium'
  tag gtitle: 'SRG-APP-000516-WSR-000174'
  tag gid: 'V-NGNX-WB-000102'
  tag rid: 'SV-NGNX-WB-000102'
  tag stig_id: 'NGNX-WB-000102'
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']

  # Check for setting in HTTP block
  describe nginx_conf_custom(input('nginx_conf_path')).params['http'][0]['ssl_session_tickets'] do
    it { should include ['off'] }
  end

  # Check server blocks to ensure setting doesn't exist or is off
  servers = nginx_conf_custom(input('nginx_conf_path')).servers

  servers.each do |server|
    describe.one do
      describe "Checking server block: #{server.params['server_name']}" do
        it 'its ssl_session_tickets should be off' do
          expect(server.params['ssl_session_tickets']).to include(['off'])
        end
      end
      describe "Checking server block: #{server.params['server_name']}" do
        it 'its ssl_session_tickets should not exist' do
          expect(server.params['ssl_session_tickets']).to be nil
        end
      end
    end
  end

  # Check location blocks to ensure setting doesn't exist or is off
  locations = nginx_conf_custom(input('nginx_conf_path')).locations

  locations.each do |location|
    describe.one do
      describe "Checking location block: #{location.params['_']}" do
        it 'its ssl_session_tickets should be off' do
          expect(location.params['ssl_session_tickets']).to include(['off'])
        end
      end
      describe "Checking location block: #{location.params['_']}" do
        it 'its ssl_session_tickets should not exist' do
          expect(location.params['ssl_session_tickets']).to be nil
        end
      end
    end
  end
end
