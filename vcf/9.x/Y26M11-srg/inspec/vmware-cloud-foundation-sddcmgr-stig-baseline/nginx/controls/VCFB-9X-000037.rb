control 'VCFB-9X-000037' do
  title 'The VMware Cloud Foundation SDDC Manager NGINX server must be configured to use a specified IP address and port.'
  desc  "
    The web server must be configured to listen on a specified IP address and port.  Without specifying an IP address and port for the web server to utilize, the web server will listen on all IP addresses available to the hosting server.  If the web server has multiple IP addresses, i.e., a management IP address, the web server will also accept connections on the management IP address.

    Accessing the hosted application through an IP address normally used for nonapplication functions opens the possibility of user access to resources, utilities, files, ports, and protocols that are protected on the desired application IP address.
  "
  desc  'rationale', ''
  desc  'check', "
    Verify the listen directive for each server context.

    View the running configuration by running the following command:

    # nginx -T 2>&1 | sed -n \"/server\\s{/,/location.*{/p\" | grep listen

    Example configuration:

    listen 127.0.0.1:80 default_server;
    listen [::1]:80 default_server;
    listen 443 ssl;
    listen [::]:443 ssl;

    If the configured \"listen\" directives do not define a specified IP/hostname and/or port, this is a finding.

    If the configured \"listen\" directives for ssl enabled server contexts do not have an address specified, this is NOT a finding.
  "
  desc  'fix', "
    SSL enabled server contexts intended to listen on all interfaces are acceptable. Server contexts without ssl enabled that are proxied locally should define \"localhost\" or \"127.0.0.1\" for the address.

    Navigate to and open:

    The nginx.conf (/etc/nginx/nginx.conf by default or the included file where the server is defined) file.

    Update the server's listen directive, for example:

    server {
            server_name localhost;
            listen 127.0.0.1:80 default_server;
            listen [::1]:80 default_server;

    server {
            listen 443 ssl;
            listen [::]:443 ssl;

    Reload the NGINX configuration by running the following command:

    # nginx -s reload
  "
  impact 0.5
  tag severity: 'medium'
  tag gtitle: 'SRG-APP-000142-WSR-000089'
  tag satisfies: ['SRG-APP-000383-WSR-000175']
  tag gid: 'V-VCFB-9X-000037'
  tag rid: 'SV-VCFB-9X-000037'
  tag stig_id: 'VCFB-9X-000037'
  tag cci: ['CCI-000382', 'CCI-001762']
  tag nist: ['CM-7 (1) (b)', 'CM-7 b']

  servers = nginx_conf_custom(input('nginx_conf_path')).servers
  listen_addresses_ports = input('listen_addresses_ports')

  # Check each server block and each listen directive for the SSL option
  if !servers.empty?
    servers.each do |server|
      server.params['listen'].each do |listen|
        describe "Checking listen directive: #{listen}" do
          it 'should have a known IP:Port defined' do
            expect(listen[0]).to be_in listen_addresses_ports
          end
        end
      end
    end
  else
    describe 'No server directives defined' do
      skip 'No server directives defined...skipping...'
    end
  end
end
