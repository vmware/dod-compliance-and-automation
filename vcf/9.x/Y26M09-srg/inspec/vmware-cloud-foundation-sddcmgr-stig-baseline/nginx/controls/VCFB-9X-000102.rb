control 'VCFB-9X-000102' do
  title 'The VMware Cloud Foundation SDDC Manager NGINX server must disable SSL session tickets.'
  desc  "Perfect forward secrecy is an encryption mechanism that enables past session keys to not be compromised even if the server's private key is compromised. If an attacker recorded all traffic to a server and stored it and then obtained the private key without perfect forward secrecy, all communications would be compromised. With perfect forward secrecy, session keys are generated using Diffie-Hellman for every session a user initiates, which isolates session compromise to only that communication session. Allowing session resumption breaks perfect forward secrecy; this expands the surface area for an attacker to compromise past sessions and communications with a server if they are able to compromise the session."
  desc  'rationale', ''
  desc  'check', "
    If TLS 1.3 only is configured, this is NOT applicable.

    Verify that SSL session tickets are disabled.

    View the running configuration by running the following command:

    # nginx -T 2>&1 | sed -n '/\\sserver\\s{/{:a;N;/.*location/!ba;/.*listen.*ssl/p}' | grep ssl_session_tickets

    Example configuration:

    http {
      ssl_session_tickets off;
    }

    If the \"ssl_session_tickets\" directive is set to \"on\", this is a finding.
  "
  desc 'fix', "
    Navigate to and open:

    The nginx.conf (/etc/nginx/nginx.conf by default) file.

    Add the \"ssl_session_tickets\" directive to the http context, for example:

    ssl_session_tickets off;

    Remove any \"ssl_session_tickets\" from server and location contexts.

    Reload the NGINX configuration by running the following command:

    # nginx -s reload
  "
  impact 0.5
  tag severity: 'medium'
  tag gtitle: 'SRG-APP-000516-WSR-000174'
  tag gid: 'V-VCFB-9X-000102'
  tag rid: 'SV-VCFB-9X-000102'
  tag stig_id: 'VCFB-9X-000102'
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']

  servers = nginx_conf_custom(input('nginx_conf_path')).servers

  if !servers.empty?
    servers.each do |server|
      next unless server.params['listen'].flatten.include?('ssl')
      protocols = server.params['ssl_protocols'].flatten.join(',')
      if !protocols.equal?('TLSv1.3')
        describe.one do
          describe "ssl_session_tickets in server context with listener: #{server.params['listen'].flatten}" do
            subject { server.params['ssl_session_tickets'] }
            it { should include ['off'] }
          end
          describe "ssl_session_tickets in server context with listener: #{server.params['listen'].flatten}" do
            subject { server.params['ssl_session_tickets'] }
            it { should be nil }
          end
        end
      else
        describe "ssl_session_tickets is N/A to server contexts with TLS 1.3 only enabled. Server context with listener: #{server.params['listen'].flatten}" do
          subject { server.params['ssl_session_tickets'] }
          it { should be nil }
        end
        describe "ssl_session_tickets is N/A to server contexts with TLS 1.3 only enabled. Server context with listener: #{server.params['listen'].flatten}" do
          subject { server.params['ssl_protocols'].flatten }
          it { should cmp ['TLSv1.3'] }
        end
      end
    end
  else
    describe 'No server contexts found...skipping.' do
      skip 'No server contexts found...skipping.'
    end
  end
end
