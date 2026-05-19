control 'VCFQ-9X-000048' do
  title 'The VMware Cloud Foundation Operations Fleet Management NGINX server must secure session cookies exchanged between NGINX and the client.'
  desc  "
    Cookies are used to exchange data between the web server and the client. Cookies, such as a session cookie, may contain session information and user credentials used to maintain a persistent connection between the user and the hosted application since HTTP/HTTPS is a stateless protocol.

    When the cookie parameters are not set properly (i.e., domain and path parameters), cookies can be shared within hosted applications residing on the same web server or to applications hosted on different web servers residing on the same domain.
  "
  desc  'rationale', ''
  desc  'check', "
    Verify a header is configured to configure session cookie security. This can be done by specifying the \"HttpOnly\" and \"Secure\" cookie options through the Set-Cookie header or for proxied servers with the \"proxy_cookie_path\" directive.

    View the running configuration by running the following command:

    # nginx -T 2>&1 | sed -n \"/^http\\s{/,/server\\s{/p\" | grep Set-Cookie

    Example configuration:

    server {
      add_header Set-Cookie \"Path=/; HttpOnly; Secure\";
    }

    or

    http {
      proxy_cookie_path / \"/; HTTPOnly; Secure\";
    }

    If a \"Set-Cookie\" header is not configured for all servers and locations with the \"HttpOnly\" and \"Secure\" parameters, this is a finding.

    If cookies are alternatively secured with the \"proxy_cookie_path\" directive with the \"HttpOnly\" and \"Secure\" parameters, this is NOT a finding.

    Note: There can be several add_header directives. These directives are inherited from the previous configuration level if and only if there are no add_header directives defined on the current level so care must be taken if add_header is defined at multiple levels to include headers configured at a higher level.
  "
  desc 'fix', "
    Navigate to and open:

    The nginx.conf (/etc/nginx/nginx.conf by default or the included file where the server is defined) file.

    Add or update the \"add_header Set-Cookie\" directive, for example:

    add_header Set-Cookie \"Path=/; HttpOnly; Secure\";

    Reload the NGINX configuration by running the following command:

    # nginx -s reload

    Note: There can be several add_header directives. These directives are inherited from the previous configuration level if and only if there are no add_header directives defined on the current level so care must be taken if add_header is defined at multiple levels to include headers configured at a higher level.
  "
  impact 0.5
  tag severity: 'medium'
  tag gtitle: 'SRG-APP-000223-WSR-000011'
  tag satisfies: ['SRG-APP-000439-WSR-000154', 'SRG-APP-000439-WSR-000155']
  tag gid: 'V-VCFQ-9X-000048'
  tag rid: 'SV-VCFQ-9X-000048'
  tag stig_id: 'VCFQ-9X-000048'
  tag cci: ['CCI-001664', 'CCI-002418']
  tag nist: ['SC-23 (3)', 'SC-8']

  http_block_headers = nginx_conf_custom(input('nginx_conf_path')).params['http'][0]['add_header']
  proxy_cookie_path = nginx_conf_custom(input('nginx_conf_path')).params['http'][0]['proxy_cookie_path']
  servers = nginx_conf_custom(input('nginx_conf_path')).servers
  locations = nginx_conf_custom(input('nginx_conf_path')).locations
  header_value = ['Set-Cookie', 'Path=/; HttpOnly; Secure']
  header_name = 'Set-Cookie'
  proxy_header_value = ['/', '/; HTTPOnly; Secure']

  if proxy_cookie_path
    describe nginx_conf_custom(input('nginx_conf_path')).params['http'][0]['proxy_cookie_path'] do
      it { should include proxy_header_value }
    end
    proxyfound = true
  # Check to see if headers exist in the http block, if they do if any are defined in a server or location block must also include this header
  elsif http_block_headers
    describe http_block_headers do
      it { should include header_value }
    end
    # Since headers are defined at the http level we need to check if they are defined lower. If not it's ok but if there are any defined they should include the headers defined at the http level
    servers.each do |server|
      next unless server.params['listen'].flatten.include?('ssl')
      server_headers = server.params['add_header']
      next unless server_headers
      describe "Found headers defined in server: #{server.params['server_name']}" do
        it "should have a #{header_name} header" do
          expect(server_headers).to include(header_value)
        end
      end
    end
  # If none exist in the http block check the server and location blocks
  else
    # Check each server block
    servers.each do |server|
      next unless server.params['listen'].flatten.include?('ssl')
      server_headers = server.params['add_header']
      if server_headers
        describe "Found headers defined in server: #{server.params['server_name']}" do
          it "should have a #{header_name} header" do
            expect(server_headers).to include(header_value)
          end
        end
      else
        describe "No headers defined in server: #{server.params['server_name']}" do
          it "should have a #{header_name} header" do
            expect(server_headers).to_not eq nil
          end
        end
      end
    end
  end
  unless proxyfound
    locations.each do |location|
      location_headers = location.params['add_header']
      next unless location_headers
      describe "Found headers defined in location: #{location.params['_']}" do
        it "should have a #{header_name} header" do
          expect(location_headers).to include(header_value)
        end
      end
    end
  end
end
