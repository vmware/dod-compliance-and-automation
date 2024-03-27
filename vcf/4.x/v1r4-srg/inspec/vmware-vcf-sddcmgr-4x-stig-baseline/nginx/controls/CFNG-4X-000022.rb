control 'CFNG-4X-000022' do
  title 'The SDDC Manager NGINX service must protect against MIME sniffing.'
  desc  "
    MIME sniffing was, and still is, a technique used by some web browsers to examine the content of a particular asset. This is done for the purpose of determining an asset's file format. This technique is useful in the event that there is not enough metadata information present for a particular asset, thus leaving the possibility that the browser interprets the asset incorrectly.

    Although MIME sniffing can be useful to determine an asset's correct file format, it can also cause a security vulnerability. This vulnerability can be quite dangerous both for site owners as well as site visitors. This is because an attacker can leverage MIME sniffing to send an XSS (Cross Site Scripting) attack.
  "
  desc  'rationale', ''
  desc  'check', "
    At the command line, run the following command:

    # nginx -T 2>&1 | sed -n \"/^.*server\\s{/,/.*location\\s.*{/p\" | grep \"add_header X-Content-Type-Options\"

    add_header X-Content-Type-Options nosniff;

    There should be one result for each server defined in Nginx.

    If the output does not match the expected result or include nosniff, this is a finding.
  "
  desc 'fix', "
    Navigate to and open:

    The nginx.conf (/etc/nginx/nginx.conf by default) file.

    Add the following line in the server context for each server defined in Nginx:

    add_header X-Content-Type-Options nosniff;

    At the command line, run the following command:

    # nginx -s reload
  "
  impact 0.5
  tag severity: 'medium'
  tag gtitle: 'SRG-APP-000516-WSR-000174'
  tag gid: 'V-CFNG-4X-000022'
  tag rid: 'SV-CFNG-4X-000022'
  tag stig_id: 'CFNG-4X-000022'
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
    # Check each server block and each listen directive for the SSL option
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
