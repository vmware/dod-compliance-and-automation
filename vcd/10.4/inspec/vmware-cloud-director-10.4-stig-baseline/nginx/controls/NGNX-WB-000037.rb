control 'NGNX-WB-000037' do
  title 'NGINX must be configured to use a specified IP address and port.'
  desc  "
    The web server must be configured to listen on a specified IP address and port.  Without specifying an IP address and port for the web server to utilize, the web server will listen on all IP addresses available to the hosting server.  If the web server has multiple IP addresses, i.e., a management IP address, the web server will also accept connections on the management IP address.

    Accessing the hosted application through an IP address normally used for non-application functions opens the possibility of user access to resources, utilities, files, ports, and protocols that are protected on the desired application IP address.
  "
  desc  'rationale', ''
  desc  'check', "
    Verify listen directive for each server block.

    View the running configuration by running the following command:

    # nginx -T

    Example configuration:

    server {
      listen 10.10.10.10:443 ssl;
    }

    If the the configured listen directives in service blocks do not define a specified IP/hostname and port, this is a finding.
  "
  desc 'fix', "
    Navigate to and open:

    The nginx.conf (/etc/nginx/nginx.conf by default or the included file where the server is defined) file.

    Update the servers listen directive, for example:

    listen 10.10.10.10:443 ssl;

    Reload the NGINX configuration by running the following command:

    # nginx -s reload
  "
  impact 0.5
  tag severity: 'medium'
  tag gtitle: 'SRG-APP-000142-WSR-000089'
  tag satisfies: ['SRG-APP-000383-WSR-000175']
  tag gid: nil
  tag rid: nil
  tag stig_id: 'NGNX-WB-000037'
  tag cci: ['CCI-000382', 'CCI-001762']
  tag nist: ['CM-7 b', 'CM-7 (1) (b)']

  servers = nginx_conf_custom(input('nginx_conf_path')).servers
  listen_addresses_ports = input('listen_addresses_ports')

  # Check each server block and each listen directive for the SSL option
  servers.each do |server|
    server.params['listen'].each do |listen|
      describe "Checking listen directive: #{listen}" do
        it 'should have a known IP:Port defined' do
          expect(listen[0]).to be_in listen_addresses_ports
        end
      end
    end
  end
end
