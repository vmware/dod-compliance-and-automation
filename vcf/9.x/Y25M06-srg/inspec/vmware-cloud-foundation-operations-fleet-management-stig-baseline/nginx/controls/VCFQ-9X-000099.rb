control 'VCFQ-9X-000099' do
  title 'The VMware Cloud Foundation Operations Fleet Management NGINX server must disable server side includes.'
  desc  'Disabling server side includes prevents the exploitation of the web server by preventing the potential injection of scripts and remote code execution through the SSI functionality.'
  desc  'rationale', ''
  desc  'check', "
    Verify server side includes are off.

    View the running configuration by running the following command:

    # nginx -T 2>&1 | grep \"ssi\"

    Example configuration:

    http {
      ssi off;
    }

    If the directive \"ssi\" is configured and set to on, this is a finding.

    If the directive \"ssi\" is not configured, this is NOT a finding.

    Note: The \"ssi\" directive is off by default if not explicitly defined.
  "
  desc 'fix', "
    Navigate to and open:

    The nginx.conf (/etc/nginx/nginx.conf by default or the included file where the directive was configured) file.

    Remove the \"ssi on;\" statement.

    Reload the NGINX configuration by running the following command:

    # nginx -s reload
  "
  impact 0.5
  tag severity: 'medium'
  tag gtitle: 'SRG-APP-000516-WSR-000174'
  tag gid: 'V-VCFQ-9X-000099'
  tag rid: 'SV-VCFQ-9X-000099'
  tag stig_id: 'VCFQ-9X-000099'
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']

  https = nginx_conf_custom(input('nginx_conf_path')).params['http']
  servers = nginx_conf_custom(input('nginx_conf_path')).servers
  locations = nginx_conf_custom(input('nginx_conf_path')).locations

  if !https.empty?
    https.each do |http|
      describe.one do
        describe 'SSI configured in HTTP context' do
          subject { http['ssi'] }
          it { should include ['off'] }
        end
        describe 'SSI configured in HTTP context' do
          subject { http['ssi'] }
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
      describe.one do
        describe "Found ssi defined in server context with listener: #{server.params['listen']}" do
          subject { server.params['ssi'] }
          it { should include ['off'] }
        end
        describe "SSI directive not defined in server context with listener: #{server.params['listen']}" do
          subject { server.params['ssi'] }
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
      describe.one do
        describe "Found ssi defined in location context: #{location.params['_']}" do
          subject { location.params['ssi'] }
          it { should include ['off'] }
        end
        describe "SSI directive not defined in location context: #{location.params['_']}" do
          subject { location.params['ssi'] }
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
