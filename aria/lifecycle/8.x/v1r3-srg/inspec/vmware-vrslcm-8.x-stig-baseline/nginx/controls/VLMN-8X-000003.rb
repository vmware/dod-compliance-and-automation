control 'VLMN-8X-000003' do
  title 'The VMware Aria Suite Lifecycle web service must enable SSL.'
  desc  "
    The web server has several remote communications channels. Examples are user requests via http/https, communication to a backend database, or communication to authenticate users. The encryption used to communicate must match the data that is being retrieved or presented.

    Methods of communication are http for publicly displayed information, https to encrypt when user data is being transmitted, VPN tunneling, or other encryption methods to a database.
  "
  desc  'rationale', ''
  desc  'check', "
    Verify ssl is enabled for each server block that is not a redirect.

    View the running configuration by running the following command:

    # nginx -T

    Example configuration:

    server {
      listen 443 ssl;
    }

    If the ssl option is not specified on the listen directive for a server block that is not a redirect, this is a finding.
  "
  desc 'fix', "
    Navigate to and open the nginx.conf file (/etc/nginx/nginx.conf by default or the included file where the server is defined).

    Add the ssl option to the servers listen directive, for example:

    listen 443 ssl;

    Reload the configuration by running the following command:

    # nginx -s reload

    Note: The ssl_certificate and ssl_certificate_key also need to be defined in order for SSL to work.
  "
  impact 0.5
  tag severity: 'medium'
  tag gtitle: 'SRG-APP-000014-WSR-000006'
  tag satisfies: ['SRG-APP-000172-WSR-000104', 'SRG-APP-000439-WSR-000152']
  tag gid: 'V-VLMN-8X-000003'
  tag rid: 'SV-VLMN-8X-000003'
  tag stig_id: 'VLMN-8X-000003'
  tag cci: ['CCI-000068', 'CCI-000197', 'CCI-002418']
  tag nist: ['AC-17 (2)', 'IA-5 (1) (c)', 'SC-8']

  servers = nginx_conf_custom(input('nginx_conf_path')).servers

  # Check each server block and each listen directive for the SSL option
  if !servers.empty?
    servers.each do |server|
      server.params['listen'].each do |listen|
        if listen.include?('80')
          impact 0.0
          describe 'Verify port 80 redirect' do
            skip { 'Verify port 80 is set to redirect to a secure port' }
          end
        else
          describe "Checking listen directive: #{listen}" do
            it 'should have SSL enabled' do
              expect(listen).to include('ssl')
            end
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
