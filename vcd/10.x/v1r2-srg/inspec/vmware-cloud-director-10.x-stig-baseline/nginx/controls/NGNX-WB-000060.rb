control 'NGNX-WB-000060' do
  title 'NGINX must restrict the ability of users to launch Denial of Service (DoS) attacks against other information systems or networks.'
  desc  'A web server can limit the ability of the web server being used in a DoS attack through several methods. The methods employed will depend upon the hosted applications and their resource needs for proper operation. '
  desc  'rationale', ''
  desc  'check', "
    Verify a request shared memory zone has been established in the http block to track connections per IP.

    View the running configuration by running the following command:

    # nginx -T

    Example configuration:

    http {
      limit_req_zone $binary_remote_addr zone=req_per_ip:10m rate=100r/s;
      limit_req zone=req_per_ip burst=100 nodelay;
    }

    If the limit_req_zone option is not configured in the http block to limit connections per IP, this is a finding.

    If the limit_req option is not configured in the http block to limit connections per IP, this is a finding.

    Note: limit_req directives under server or location blocks are acceptable to modify limits based on application needs as long as they are not disabled.
  "
  desc 'fix', "
    Navigate to and open:

    The nginx.conf (/etc/nginx/nginx.conf by default) file.

    Add the following or similar line(s) in the http block:

    limit_req_zone $binary_remote_addr zone=req_per_ip:10m rate=100r/s;
    limit_req zone=req_per_ip burst=100 nodelay;

    Note: Substitute values appropriate for the web server.

    Reload the NGINX configuration by running the following command:

    # nginx -s reload
  "
  impact 0.5
  tag severity: 'medium'
  tag gtitle: 'SRG-APP-000246-WSR-000149'
  tag satisfies: ['SRG-APP-000435-WSR-000148']
  tag gid: 'V-NGNX-WB-000060'
  tag rid: 'SV-NGNX-WB-000060'
  tag stig_id: 'NGNX-WB-000060'
  tag cci: ['CCI-001094', 'CCI-002385']
  tag nist: ['SC-5 (1)', 'SC-5 a']

  nginx_limit_req_rate = input('nginx_limit_req_rate')
  nginx_limit_req_burst = input('nginx_limit_req_burst')
  nginx_limit_req_zone = input('nginx_limit_req_zone')

  describe nginx_conf_custom(input('nginx_conf_path')).params['http'][0]['limit_req'] do
    it { should include ['zone=req_per_ip', "burst=#{nginx_limit_req_burst}", 'nodelay'] }
  end

  describe nginx_conf_custom(input('nginx_conf_path')).params['http'][0]['limit_req_zone'] do
    it { should include ['$binary_remote_addr', "zone=#{nginx_limit_req_zone}", "rate=#{nginx_limit_req_rate}"] }
  end
end
