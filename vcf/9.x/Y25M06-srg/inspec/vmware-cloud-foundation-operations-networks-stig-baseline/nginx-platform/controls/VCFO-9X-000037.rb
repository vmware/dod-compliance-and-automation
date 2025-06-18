control 'VCFO-9X-000037' do
  title 'The VMware Cloud Foundation Operations for Networks Platform NGINX server must be configured to use a specified IP address and port.'
  desc  "
    The web server must be configured to listen on a specified IP address and port.  Without specifying an IP address and port for the web server to utilize, the web server will listen on all IP addresses available to the hosting server.  If the web server has multiple IP addresses, i.e., a management IP address, the web server will also accept connections on the management IP address.

    Accessing the hosted application through an IP address normally used for nonapplication functions opens the possibility of user access to resources, utilities, files, ports, and protocols that are protected on the desired application IP address.
  "
  desc  'rationale', ''
  desc  'check', "
    Verify the listen directive for each server context.

    View the running configuration by running the following command:

    # nginx -T 2>&1 | sed -n '/server\\s{/{:a;N;/.*location/!ba;/listen.*/p}' | grep listen | grep -vE '80|#'

    Example configuration:

    listen localhost:6060;
    listen localhost:3100;
    listen 443 ssl http2;
    listen localhost:7070;
    listen localhost:7071;
    listen localhost:7074;
    listen localhost:7072;

    If the configured \"listen\" directives do not define a specified IP/hostname and port, this is a finding.

    If the configured \"listen\" directives for ssl enabled server contexts do not have an address specified, this is NOT a finding.
  "
  desc  'fix', "
    SSL enabled server contexts intended to listen on all interfaces are acceptable. Server contexts without ssl enabled that are proxied locally should define \"localhost\" or \"127.0.0.1\" for the address.

    Navigate to and open:

    The /etc/nginx/sites-available/vnera file.

    Update the server's listen directive, for example:

    # nginx -T 2>&1 | sed -n '/server\\s{/{:a;N;/.*location/!ba;/listen.*/p}' | grep listen | grep -vE '80|#'

    Example configuration:

    listen localhost:6060;
    listen localhost:3100;
    listen localhost:7070;
    listen localhost:7071;
    listen localhost:7074;
    listen localhost:7072;

    Reload the NGINX configuration by running the following command:

    # nginx -s reload
  "
  impact 0.5
  tag severity: 'medium'
  tag gtitle: 'SRG-APP-000142-WSR-000089'
  tag satisfies: ['SRG-APP-000383-WSR-000175']
  tag gid: 'V-VCFO-9X-000037'
  tag rid: 'SV-VCFO-9X-000037'
  tag stig_id: 'VCFO-9X-000037'
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
