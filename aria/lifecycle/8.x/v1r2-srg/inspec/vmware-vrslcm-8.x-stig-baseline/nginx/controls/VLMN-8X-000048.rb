control 'VLMN-8X-000048' do
  title 'Cookies exchanged between the VMware Aria Suite Lifecycle web service and a client, such as session cookies, must have security settings that disallow cookie access outside the originating web server and hosted application.'
  desc  "
    Cookies are used to exchange data between the web server and the client. Cookies, such as a session cookie, may contain session information and user credentials used to maintain a persistent connection between the user and the hosted application since HTTP/HTTPS is a stateless protocol.

    When the cookie parameters are not set properly (i.e., domain and path parameters), cookies can be shared within hosted applications residing on the same web server or to applications hosted on different web servers residing on the same domain.
  "
  desc  'rationale', ''
  desc  'check', "
    Verify a header is configured to configure cookie security.

    View the running configuration by running the following command:

    # nginx -T

    Example configuration:

    server {
      add_header Set-Cookie \"Path=/; HttpOnly; Secure\";
    }

    If a header is not configured as shown in the example in the http, server, or location block, this is a finding.

    Note: There can be several add_header directives. These directives are inherited from the previous configuration level if and only if there are no add_header directives defined on the current level so care must be taken if add_header is defined at multiple levels to include headers configured at a higher level.
  "
  desc 'fix', "
    Navigate to and open the nginx.conf file (/etc/nginx/nginx.conf by default or the included file where the server is defined).

    Add or update the \"add_header Set-Cookie\" directive, for example:

    add_header Set-Cookie \"Path=/; HttpOnly; Secure\";

    Reload the configuration by running the following command:

    # nginx -s reload

    Note: There can be several add_header directives. These directives are inherited from the previous configuration level if and only if there are no add_header directives defined on the current level so care must be taken if add_header is defined at multiple levels to include headers configured at a higher level.
  "
  impact 0.5
  tag severity: 'medium'
  tag gtitle: 'SRG-APP-000223-WSR-000011'
  tag satisfies: ['SRG-APP-000439-WSR-000154', 'SRG-APP-000439-WSR-000155']
  tag gid: 'V-VLMN-8X-000048'
  tag rid: 'SV-VLMN-8X-000048'
  tag stig_id: 'VLMN-8X-000048'
  tag cci: ['CCI-001664', 'CCI-002418']
  tag nist: ['SC-23 (3)', 'SC-8']

  http_block_headers = nginx_conf_custom(input('nginx_conf_path')).params['http'][0]['add_header']
  servers = nginx_conf_custom(input('nginx_conf_path')).servers
  locations = nginx_conf_custom(input('nginx_conf_path')).locations
  header_value = 'Path=/; HttpOnly; Secure'
  header_name = 'Set-Cookie'

  http_header_found = false

  # Check to see if headers exist in the http block, if they do if any are defined in a server or location block must also include this header
  if http_block_headers
    http_header = http_block_headers.find { |item| item[0] == header_name }
    if http_header
      http_header_found = true

      describe 'Found headers defined in http block' do
        it "should have a #{header_name} header" do
          expect(http_header[1]).to include(header_value)
        end
      end
    end
  end

  # Check each server block and each listen directive for the SSL option
  # If header defined at the server level, ensure value is correct
  servers.each do |server|
    next unless server.params['listen'].flatten.include?('ssl')
    server_headers = server.params['add_header'].find { |item| item[0] == header_name }
    if server_headers
      describe "Found headers defined in server: #{server.params['server_name']}" do
        it "should have a #{header_name} header" do
          expect(server_headers[1]).to include(header_value)
        end
      end
    elsif !http_header_found
      # If header not defined at the Host level, and also not defined here, then it should be...
      describe "No headers defined in server: #{server.params['server_name']}" do
        it "should have a #{header_name} header" do
          expect(server_headers).to_not eq nil
        end
      end
    end
  end

  # If header defined at a location block, make sure the value is correct
  locations.each do |location|
    location_headers = location.params['add_header']
    next unless location_headers
    loc_header = location_headers.find { |item| item[0] == header_name }
    next unless loc_header
    describe "Found headers defined in location: #{location.params['_']}" do
      it "should have a #{header_name} header" do
        expect(loc_header[1]).to include(header_value)
      end
    end
  end
end
