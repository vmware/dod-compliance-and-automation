control 'VCFO-9X-000100' do
  title 'The VMware Cloud Foundation Operations for Networks Platform NGINX server must not disable keep alive timeouts.'
  desc  "
    The keep alive timeout sets a timeout during which a keep-alive client connection will stay open on the server side.

    Setting a keep alive timeout on the server side helps mitigate denial of service attacks that establish too many persistent connections, exhausting server resources.
  "
  desc  'rationale', ''
  desc  'check', "
    Verify the keep alive timeout is not disabled.

    View the running configuration by running the following command:

    # nginx -T 2>&1 | grep \"keepalive_timeout\"

    Example configuration:

    http {
      keepalive_timeout 60s;
    }

    If the directive \"keepalive_timeout\" is configured and set to 0 or more than the default of 75, this is a finding.

    If the directive \"keepalive_timeout\" is not configured, this is NOT a finding.
  "
  desc 'fix', "
    Navigate to and open:

    The nginx.conf (/etc/nginx/nginx.conf by default or the included file where the directive was configured) file.

    Remove or update the \"keepalive_timeout\" directive to a value > 0 and <= 75, for example:

    keepalive_timeout 60s;

    Reload the NGINX configuration by running the following command:

    # nginx -s reload
  "
  impact 0.5
  tag severity: 'medium'
  tag gtitle: 'SRG-APP-000516-WSR-000174'
  tag gid: 'V-VCFO-9X-000100'
  tag rid: 'SV-VCFO-9X-000100'
  tag stig_id: 'VCFO-9X-000100'
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']

  https = nginx_conf_custom(input('nginx_conf_path')).params['http']
  servers = nginx_conf_custom(input('nginx_conf_path')).servers
  locations = nginx_conf_custom(input('nginx_conf_path')).locations

  if !https.empty?
    https.each do |http|
      if http['keepalive_timeout']
        describe 'keepalive_timeout configured in HTTP context' do
          # Trim off the s off the end of the value
          subject { http['keepalive_timeout'].tr('s', '') }
          it { should cmp > 0 }
          it { should cmp <= 75 }
        end
      else
        describe 'keepalive_timeout in HTTP context' do
          subject { http['keepalive_timeout'] }
          it { should cmp nil }
        end
      end
    end
  else
    describe 'No HTTP contexts found...skipping.' do
      skip 'No HTTP contexts found...skipping.'
    end
  end
  if !servers.empty?
    servers.each do |server|
      if server.params['keepalive_timeout']
        describe "Found keepalive_timeout defined in server context with listener: #{server.params['listen']}" do
          # Trim off the s off the end of the value
          subject { server.params['keepalive_timeout'].tr('s', '') }
          it { should cmp > 0 }
          it { should cmp <= 75 }
        end
      else
        describe "keepalive_timeout directive not defined in server context with listener: #{server.params['listen']}" do
          subject { server.params['keepalive_timeout'] }
          it { should cmp nil }
        end
      end
    end
  else
    describe 'No server contexts found...skipping.' do
      skip 'No server contexts found...skipping.'
    end
  end
  if !locations.empty?
    locations.each do |location|
      if location.params['keepalive_timeout']
        describe "Found keepalive_timeout directive in location context: #{location.params['_']}" do
          # Trim off the s off the end of the value
          subject { location.params['keepalive_timeout'].tr('s', '') }
          it { should cmp > 0 }
          it { should cmp <= 75 }
        end
      else
        describe "keepalive_timeout directive not defined in location context: #{location.params['_']}" do
          subject { location.params['keepalive_timeout'] }
          it { should cmp nil }
        end
      end
    end
  else
    describe 'No location contexts found...skipping.' do
      skip 'No location contexts found...skipping.'
    end
  end
end
