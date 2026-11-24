control 'VCFO-9X-000003' do
  title 'The VMware Cloud Foundation Operations for Networks Platform NGINX server must enable SSL on external server contexts.'
  desc  "
    The web server has several remote communications channels. Examples are user requests via http/https, communication to a backend database, or communication to authenticate users. The encryption used to communicate must match the data that is being retrieved or presented.

    Methods of communication are http for publicly displayed information, https to encrypt when user data is being transmitted, VPN tunneling, or other encryption methods to a database.
  "
  desc  'rationale', ''
  desc  'check', "
    If a server context is not listening on an externally accessible interface, this is Not Applicable for that server context.

    Verify ssl is enabled for each server context.

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

    If the \"ssl\" option is not specified on the listen directive for a server context that is externally accessible, this is a finding.
  "
  desc 'fix', "
    Navigate to and open:

    The /etc/nginx/sites-available/vnera file.

    Add the ssl option to the server's listen directive, for example:

    listen 443 ssl;

    Reload the NGINX configuration by running the following command:

    # nginx -s reload

    Note: The ssl_certificate and ssl_certificate_key also need to be defined in order for SSL to work.
  "
  impact 0.5
  tag severity: 'medium'
  tag gtitle: 'SRG-APP-000014-WSR-000006'
  tag satisfies: ['SRG-APP-000172-WSR-000104', 'SRG-APP-000439-WSR-000152']
  tag gid: 'V-VCFO-9X-000003'
  tag rid: 'SV-VCFO-9X-000003'
  tag stig_id: 'VCFO-9X-000003'
  tag cci: ['CCI-000068', 'CCI-000197', 'CCI-002418']
  tag nist: ['AC-17 (2)', 'IA-5 (1) (c)', 'SC-8']

  servers = nginx_conf_custom(input('nginx_conf_path')).servers

  # Check each server block and each listen directive for the SSL option
  if !servers.empty?
    servers.each do |server|
      server.params['listen'].each do |listen|
        if listen.include?('ssl')
          describe "Listen directive: #{listen}" do
            subject { listen }
            it { should include 'ssl' }
          end
        else
          matches = false
          listen.each do |listendirs|
            # Match listen options that contain decimals, *, [, or the word localhost to find only the address:port values
            next unless listendirs.match?(/^[\d\*\[]+|localhost/)
            matches = true
            describe "Listen directive: #{listen} does not have SSL enabled and should only listen on internal interfaces" do
              subject { listendirs }
              it { should include('127.0.0.1').or include('localhost').or include('::1').or include('80') }
            end
          end
          unless matches
            describe "No matches found in listen directive: #{listen} for addresses or ports. Matches" do
              subject { matches }
              it { should be true }
            end
          end
        end
      end
    end
  else
    describe 'No server contexts found...skipping...' do
      skip 'No server contexts found...skipping...'
    end
  end
end
