control 'NGNX-WB-000104' do
  title 'NGINX must protect against MIME sniffing.'
  desc  "
    MIME sniffing was, and still is, a technique used by some web browsers to examine the content of a particular asset. This is done for the purpose of determining an asset's file format. This technique is useful in the event that there is not enough metadata information present for a particular asset, thus leaving the possibility that the browser interprets the asset incorrectly.

    Although MIME sniffing can be useful to determine an asset's correct file format, it can also cause a security vulnerability. This vulnerability can be quite dangerous both for site owners as well as site visitors. This is because an attacker can leverage MIME sniffing to send an XSS (Cross Site Scripting) attack.
  "
  desc  'rationale', ''
  desc  'check', "
    Verify a header is configured to set X-Content-Type-Options.

    View the running configuration by running the following command:

    # nginx -T

    Example configuration:

    server {
      add_header X-Content-Type-Options nosniff;
    }

    If a header is not configured as shown in the example in the http, server, or location block, this is a finding.

    Note: There can be several add_header directives. These directives are inherited from the previous configuration level if and only if there are no add_header directives defined on the current level so care must be taken if add_header is defined at multiple levels to include headers configured at a higher level.
  "
  desc 'fix', "
    Navigate to and open:

    The nginx.conf (/etc/nginx/nginx.conf by default or the included file where the server is defined) file.

    Add a add_header directive, for example:

    add_header X-Content-Type-Options nosniff;

    Reload the NGINX configuration by running the following command:

    # nginx -s reload

    Note: There can be several add_header directives. These directives are inherited from the previous configuration level if and only if there are no add_header directives defined on the current level so care must be taken if add_header is defined at multiple levels to include headers configured at a higher level.
  "
  impact 0.5
  tag severity: 'medium'
  tag gtitle: 'SRG-APP-000516-WSR-000174'
  tag gid: 'V-NGNX-WB-000104'
  tag rid: 'SV-NGNX-WB-000104'
  tag stig_id: 'NGNX-WB-000104'
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']

  http_block_headers = nginx_conf_custom(input('nginx_conf_path')).params['http'][0]['add_header']
  servers = nginx_conf_custom(input('nginx_conf_path')).servers
  locations = nginx_conf_custom(input('nginx_conf_path')).locations
  header_value = ['X-Content-Type-Options', 'nosniff']
  header_name = 'X-Content-Type-Options'

  # Check to see if headers exist in the http block, if they do if any are defined in a server or location block must also include this header
  if http_block_headers
    describe http_block_headers do
      it { should include header_value }
    end
    # Since headers are defined at the http level we need to check if they are defined lower. If not it's ok but if there are any defined they should include the headers defined at the http level
    servers.each do |server|
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
