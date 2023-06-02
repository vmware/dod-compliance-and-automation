control 'CFNG-5X-000102' do
  title 'The SDDC Manager NGINX service must configure the Referrer-Policy header.'
  desc  "A Referrer header may expose sensitive data in another web server's log if you use sensitive data in your URL parameters, such as personal information, username, and password or persistent sessions. Ultimately, depending on your application design, not using a properly configured Referrer Policy may allow session hijacking, credential gathering, or sensitive data exposure in a third party's logs."
  desc  'rationale', ''
  desc  'check', "
    At the command line, run the following command:

    # nginx -T 2>&1 | sed -n \"/^.*server\\s{/,/.*location\\s.*{/p\" | grep \"add_header Referrer-Policy\"

    Example result:

    add_header Referrer-Policy \"no-referrer\";
    add_header Referrer-Policy \"no-referrer\";

    There should be one result for each server defined in Nginx.

    If the \"Referrer-Policy\" header is not configured to \"no-referrer\", this is a finding.
  "
  desc 'fix', "
    Navigate to and open:

    The nginx.conf (/etc/nginx/nginx.conf by default) file.

    Add the following line in the server context for each server defined in Nginx:

    add_header Referrer-Policy \"no-referrer\";

    At the command line, run the following command:

    # nginx -s reload
  "
  impact 0.5
  tag severity: 'medium'
  tag gtitle: 'SRG-APP-000516-WSR-000174'
  tag gid: 'V-CFNG-5X-000102'
  tag rid: 'SV-CFNG-5X-000102'
  tag stig_id: 'CFNG-5X-000102'
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']

  http_block_headers = nginx_conf_custom(input('nginx_conf_path')).params['http'][0]['add_header']
  servers = nginx_conf_custom(input('nginx_conf_path')).servers
  locations = nginx_conf_custom(input('nginx_conf_path')).locations
  header_value = ['Referrer-Policy', 'no-referrer']
  header_name = 'Referrer-Policy'

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
