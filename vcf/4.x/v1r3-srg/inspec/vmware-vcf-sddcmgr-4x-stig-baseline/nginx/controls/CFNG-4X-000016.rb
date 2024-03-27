control 'CFNG-4X-000016' do
  title 'The SDDC Manager NGINX service must not display server information in error messages.'
  desc  "
    Web servers will often display error messages to client users displaying enough information to aid in the debugging of the error. The information given back in error messages may display the web server type, version, patches installed, plug-ins and modules installed, type of code being used by the hosted application, and any backends being used for data storage.

    This information could be used by an attacker to blueprint what type of attacks might be successful. The information given to users must be minimized to not aid in the blueprinting of the web server.
  "
  desc  'rationale', ''
  desc  'check', "
    At the command line, run the following command to check the http context:

    # nginx -T 2>&1 | sed -n \"/^http\\s{/,/server\\s{/p\" | grep server_tokens

    Expected result:

    server_tokens off;

    At the command line, run the following command to check the server and location contexts:

    # nginx -T 2>&1 | sed -n -e '/\\sserver\\s{/,$p' | grep server_tokens

    Expected result:

    No output or \"server_tokens off;\"

    If the server tokens option is not configured in the http context to off, this is a finding.

    If the server tokens option specified in the server or location contexts and set to on, this is a finding.
  "
  desc 'fix', "
    Navigate to and open:

    The nginx.conf (/etc/nginx/nginx.conf by default) file.

    Add the following line in the http context:

    server_tokens off;

    And/or remove any server/location context \"server_tokens on;\" options specified.

    At the command line, run the following command:

    # nginx -s reload
  "
  impact 0.5
  tag severity: 'medium'
  tag gtitle: 'SRG-APP-000266-WSR-000159'
  tag satisfies: ['SRG-APP-000266-WSR-000160']
  tag gid: nil
  tag rid: nil
  tag stig_id: 'CFNG-4X-000016'
  tag cci: ['CCI-001312', 'CCI-001312']
  tag nist: ['SI-11 a', 'SI-11 a']

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
