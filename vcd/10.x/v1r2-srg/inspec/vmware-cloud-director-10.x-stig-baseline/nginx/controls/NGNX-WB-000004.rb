control 'NGNX-WB-000004' do
  title 'NGINX must implement HTTP Strict Transport Security (HSTS) to protect the integrity of remote sessions.'
  desc  'HTTP Strict Transport Security (HSTS) instructs web browsers to only use secure connections for all future requests when communicating with a web site. Doing so helps prevent SSL protocol attacks, SSL stripping, cookie hijacking, and other attempts to circumvent SSL protection.'
  desc  'rationale', ''
  desc  'check', "
    Verify a header is configured to configure HSTS.

    View the running configuration by running the following command:

    # nginx -T

    Example configuration:

    server {
      add_header Strict-Transport-Security max-age=15768000;
    }

    or

    server {
       add_header Strict-Transport-Security \"max-age=31536000\" always;
    }

    If a header is not configured as shown in one of the examples in the http, server, or location block, this is a finding.

    Note: There can be several add_header directives. These directives are inherited from the previous configuration level if and only if there are no add_header directives defined on the current level so care must be taken if add_header is defined at multiple levels to include headers configured at a higher level.
  "
  desc 'fix', "
    Navigate to and open:

    The nginx.conf (/etc/nginx/nginx.conf by default or the included file where the server is defined) file.

    Add a add_header directive, for example:

    add_header Strict-Transport-Security \"max-age=31536000\" always;

    Reload the NGINX configuration by running the following command:

    # nginx -s reload

    Note: There can be several add_header directives. These directives are inherited from the previous configuration level if and only if there are no add_header directives defined on the current level so care must be taken if add_header is defined at multiple levels to include headers configured at a higher level.
  "
  impact 0.5
  tag severity: 'medium'
  tag gtitle: 'SRG-APP-000015-WSR-000014'
  tag gid: 'V-NGNX-WB-000004'
  tag rid: 'SV-NGNX-WB-000004'
  tag stig_id: 'NGNX-WB-000004'
  tag cci: ['CCI-001453']
  tag nist: ['AC-17 (2)']

  http_block_headers = nginx_conf_custom(input('nginx_conf_path')).params['http'][0]['add_header']
  servers = nginx_conf_custom(input('nginx_conf_path')).servers
  locations = nginx_conf_custom(input('nginx_conf_path')).locations
  header_value = input('hsts_header')
  header_name = 'Strict-Transport-Security'

  # Check to see if headers exist in the http block, if they do if any are defined in a server or location block must also include this header
  if http_block_headers
    describe http_block_headers do
      it { should include header_value }
    end
    # Since headers are defined at the http level we need to check if they are defined lower. If not it's ok but if there are any defined they should include the headers defined at the http level
    servers.each do |server|
      server_headers = server.params['add_header']
      next unless server.params['listen'].flatten.include?('ssl') && server_headers
      describe "Found headers defined in server: #{server.params['server_name']}" do
        it "should have a #{header_name} header" do
          expect(server_headers).to include(header_value)
        end
      end
    end
  # If none exist in the http block check the server and location blocks
  else
    # Check each server block and each listen directive for the SSL option
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
