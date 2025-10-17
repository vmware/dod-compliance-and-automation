control 'NGNX-WB-000063' do
  title 'NGINX must minimize the identity of the web server in information displayed to clients.'
  desc  "
    Information needed by an attacker to begin looking for possible vulnerabilities in a web server includes any information about the web server, backend systems being accessed, and plug-ins or modules being used.

    Web servers will often display error messages to client users displaying enough information to aid in the debugging of the error. The information given back in error messages may display the web server type, version, patches installed, plug-ins and modules installed, type of code being used by the hosted application, and any backends being used for data storage.

    This information could be used by an attacker to blueprint what type of attacks might be successful. The information given to users must be minimized to not aid in the blueprinting of the web server.
  "
  desc  'rationale', ''
  desc  'check', "
    Verify that \"server_tokens\" is set to off http block to track connections per server.

    View the running configuration by running the following command:

    # nginx -T

    Example configuration:

    http {
      server_tokens off;
    }

    If \"server_tokens\" is not configured to \"off\" in the http block, this is a finding.

    If any server or location blocks configure \"server_tokens\" to \"on\", this is a finding.
  "
  desc 'fix', "
    Navigate to and open:

    The nginx.conf (/etc/nginx/nginx.conf by default) file.

    Add or update the following line in the http block:

    server_tokens off;

    Remove any \"server_token\" lines that are present in server or location blocks.

    Reload the NGINX configuration by running the following command:

    # nginx -s reload
  "
  impact 0.5
  tag severity: 'medium'
  tag gtitle: 'SRG-APP-000266-WSR-000159'
  tag satisfies: ['SRG-APP-000266-WSR-000160']
  tag gid: 'V-NGNX-WB-000063'
  tag rid: 'SV-NGNX-WB-000063'
  tag stig_id: 'NGNX-WB-000063'
  tag cci: ['CCI-001312']
  tag nist: ['SI-11 a']

  # Check for setting in HTTP block
  describe nginx_conf_custom(input('nginx_conf_path')).params['http'][0]['server_tokens'] do
    it { should include ['off'] }
  end

  # Check server blocks to ensure setting doesn't exist or is off
  servers = nginx_conf_custom(input('nginx_conf_path')).servers

  servers.each do |server|
    describe.one do
      describe "Checking server block: #{server.params['server_name']}" do
        it 'its server_tokens should be off' do
          expect(server.params['server_tokens']).to include(['off'])
        end
      end
      describe "Checking server block: #{server.params['server_name']}" do
        it 'its server_tokens should not exist' do
          expect(server.params['server_tokens']).to be nil
        end
      end
    end
  end

  # Check location blocks to ensure setting doesn't exist or is off
  locations = nginx_conf_custom(input('nginx_conf_path')).locations

  locations.each do |location|
    describe.one do
      describe "Checking location block: #{location.params['_']}" do
        it 'its server_tokens should be off' do
          expect(location.params['server_tokens']).to include(['off'])
        end
      end
      describe "Checking location block: #{location.params['_']}" do
        it 'its server_tokens should not exist' do
          expect(location.params['server_tokens']).to be nil
        end
      end
    end
  end
end
