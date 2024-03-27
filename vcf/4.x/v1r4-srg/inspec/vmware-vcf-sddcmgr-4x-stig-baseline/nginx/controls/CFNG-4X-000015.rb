control 'CFNG-4X-000015' do
  title 'The SDDC Manager NGINX service must restrict the ability of users to launch Denial of Service (DoS) attacks.'
  desc  'A web server can limit the ability of the web server being used in a DoS attack through several methods. The methods employed will depend upon the hosted applications and their resource needs for proper operation.'
  desc  'rationale', ''
  desc  'check', "
    Verify a shared memory zone has been established in the http context to track requests per IP.

    At the command line, run the following command:

    # nginx -T 2>&1 | sed -n \"/^http\\s{/,/server\\s{/p\" | grep limit_req_zone --color=always | grep \"zone=api_traffic\"

    Expected result:

    limit_req_zone $binary_remote_addr zone=api_traffic:10m rate=5000r/s;

    If the limit_req_zone option is not configured in the http context to limit requests per IP, this is a finding.

    Verify the server terminating ssl also has a limit_req statement in its server context.

    At the command line, run the following command:

    # nginx -T 2>&1 | sed -n '/\\sserver\\s{/{:a;N;/.*location/!ba;/.*listen.*ssl/p}' | grep limit_req

    Expected result:

    limit_req zone=api_traffic burst=100 nodelay;

    If the \"limit_req\" option is not configured to limit requests per IP, this is a finding.

    Note: Per server or location limit_req directives are acceptable to modify limits based on application needs as long as they are not disabled.
  "
  desc 'fix', "
    Navigate to and open:

    The nginx.conf (/etc/nginx/nginx.conf by default) file.

    Add the following or similar line in the http context:

    limit_req_zone $binary_remote_addr zone=api_traffic:10m rate=5000r/s;

    Add the following or similar line in the server context that is terminating ssl:

    limit_req zone=api_traffic burst=100 nodelay;

    At the command line, run the following command:

    # nginx -s reload
  "
  impact 0.5
  tag severity: 'medium'
  tag gtitle: 'SRG-APP-000246-WSR-000149'
  tag gid: 'V-CFNG-4X-000015'
  tag rid: 'SV-CFNG-4X-000015'
  tag stig_id: 'CFNG-4X-000015'
  tag cci: ['CCI-001094']
  tag nist: ['SC-5 (1)']

  describe nginx_conf_custom(input('nginx_conf_path')).params['http'][0]['limit_req_zone'] do
    it { should include ['$binary_remote_addr', 'zone=api_traffic:10m', 'rate=5000r/s'] }
  end
  servers = nginx_conf_custom(input('nginx_conf_path')).servers
  servers.each do |server|
    next unless server.params['listen'].flatten.include?('ssl')
    describe "Checking server block: #{server.params['server_name']}" do
      it 'its limit_req should be configured' do
        expect(server.params['limit_req']).to include ['zone=api_traffic', 'burst=100', 'nodelay']
      end
    end
  end
end
