control 'VCFB-9X-000060' do
  title 'The VMware Cloud Foundation SDDC Manager NGINX server must restrict the ability of users to launch Denial of Service (DoS) attacks against other information systems or networks.'
  desc  'A web server can limit the ability of the web server being used in a DoS attack through several methods. The methods employed will depend upon the hosted applications and their resource needs for proper operation. '
  desc  'rationale', ''
  desc  'check', "
    Verify a request shared memory zone has been established in the http context to limit requests per IP and is enabled on all SSL enabled server contexts.

    View the http context configuration by running the following command:

    # nginx -T 2>&1 | sed -n \"/^http\\s{/,/server\\s{/p\" | grep limit_req

    Example result:

    limit_req_zone $binary_remote_addr zone=api_traffic:10m rate=5000r/s;
    limit_req_zone $binary_remote_addr zone=ui_traffic:10m rate=1000r/s;
    limit_req_zone $binary_remote_addr zone=ui_file_upload:10m rate=1r/s;

    View server contexts configuration by running the following command:

    # nginx -T 2>&1 | sed -n '/\\sserver\\s{/{:a;N;/.*location/!ba;/.*listen.*ssl/p}' | grep limit_req

    Example result:

    limit_req zone=api_traffic burst=100 nodelay;

    If the \"limit_req_zone\" directive is not configured in the http context to limit requests per IP , this is a finding.

    If the \"limit_req\" directive is not configured in the http context or in each SSL enabled server context, this is a finding.

    Note: \"limit_req\" directives under server or location contexts are acceptable to modify limits based on application needs as long as they are not disabled.
  "
  desc 'fix', "
    Navigate to and open:

    The nginx.conf (/etc/nginx/nginx.conf by default) file.

    Add the following or similar line(s) in the http and server contexts:

    http {
      limit_req_zone $binary_remote_addr zone=api_traffic:10m rate=5000r/s;
      limit_req_zone $binary_remote_addr zone=ui_traffic:10m rate=1000r/s;
      limit_req_zone $binary_remote_addr zone=ui_file_upload:10m rate=1r/s;

      server {
        limit_req zone=api_traffic burst=100 nodelay;
    }

    Note: Substitute values appropriate for the web server.

    Reload the NGINX configuration by running the following command:

    # nginx -s reload
  "
  impact 0.5
  tag severity: 'medium'
  tag gtitle: 'SRG-APP-000246-WSR-000149'
  tag satisfies: ['SRG-APP-000435-WSR-000148']
  tag gid: 'V-VCFB-9X-000060'
  tag rid: 'SV-VCFB-9X-000060'
  tag stig_id: 'VCFB-9X-000060'
  tag cci: ['CCI-001094', 'CCI-002385']
  tag nist: ['SC-5 (1)', 'SC-5 a']

  nginx_limit_req_zone_name = input('nginx_limit_req_zone_name')
  nginx_limit_req_rate = input('nginx_limit_req_rate')
  nginx_limit_req_burst = input('nginx_limit_req_burst')
  nginx_limit_req_zone_size = input('nginx_limit_req_zone_size')
  servers = nginx_conf_custom(input('nginx_conf_path')).servers
  http_limit_req = nginx_conf_custom(input('nginx_conf_path')).params['http'][0]['limit_req']
  http_limit_zone = nginx_conf_custom(input('nginx_conf_path')).params['http'][0]['limit_req_zone']

  # Check for limit_req_zone to be established in the http context
  describe 'limit_req_zone configured in HTTP context' do
    subject { http_limit_zone }
    it { should include ['$binary_remote_addr', "zone=#{nginx_limit_req_zone_name}:#{nginx_limit_req_zone_size}", "rate=#{nginx_limit_req_rate}"] }
  end

  if http_limit_req
    describe nginx_conf_custom(input('nginx_conf_path')).params['http'][0]['limit_req'] do
      it { should include ["zone=#{nginx_limit_req_zone_name}", "burst=#{nginx_limit_req_burst}", 'nodelay'] }
    end
  else
    servers.each do |server|
      next unless server.params['listen'].flatten.include?('ssl')
      server_limit_req = server.params['limit_req']
      if server_limit_req
        describe "Found limit_req defined in server context with listener: #{server.params['listen'].flatten}" do
          subject { server_limit_req }
          it { should include ["zone=#{nginx_limit_req_zone_name}", "burst=#{nginx_limit_req_burst}", 'nodelay'] }
        end
      else
        describe "No limit_req defined in server context with listener: #{server.params['listen'].flatten}" do
          subject { server_limit_req }
          it { should_not be nil }
        end
      end
    end
  end
end
