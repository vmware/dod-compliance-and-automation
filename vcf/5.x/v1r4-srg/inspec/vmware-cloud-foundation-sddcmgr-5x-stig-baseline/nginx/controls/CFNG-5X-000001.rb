control 'CFNG-5X-000001' do
  title 'The SDDC Manager NGINX service must limit the number of concurrent connections per IP.'
  desc  'Web server management includes the ability to control the number of users and user sessions that utilize a web server. Limiting the number of allowed users and sessions per user is helpful in limiting risks related to several types of Denial of Service attacks.'
  desc  'rationale', ''
  desc  'check', "
    Verify a shared memory zone has been established in the http context to track connections per IP.

    At the command line, run the following command:

    # nginx -T 2>&1 | sed -n \"/^http\\s{/,/server\\s{/p\" | grep limit_conn_zone --color=always | grep \"\\$binary_remote_addr\"

    Example result:

    limit_conn_zone $binary_remote_addr zone=per_ip:10m;

    If the limit_conn_zone option is not configured in the http context to limit connections per IP, this is a finding.

    Verify the http context also has a limit_conn statement.

    At the command line, run the following command:

    # nginx -T 2>&1 | sed -n \"/^http\\s{/,/server\\s{/p\" | grep \"limit_conn per_ip\"

    Example result:

    limit_conn per_ip 100;

    If the \"limit_conn\" option is not configured in the http context to limit connections per IP, this is a finding.

    Note: Per server or location limit_conn directives are acceptable to modify limits based on application needs as long as they are not disabled.
  "
  desc 'fix', "
    Navigate to and open:

    The nginx.conf (/etc/nginx/nginx.conf by default) file.

    Add the following or similar line(s) in the http context:

    limit_conn_zone $binary_remote_addr zone=per_ip:10m;

    limit_conn per_ip 100;

    At the command line, run the following command:

    # nginx -s reload
  "
  impact 0.5
  tag severity: 'medium'
  tag gtitle: 'SRG-APP-000001-WSR-000001'
  tag gid: 'V-CFNG-5X-000001'
  tag rid: 'SV-CFNG-5X-000001'
  tag stig_id: 'CFNG-5X-000001'
  tag cci: ['CCI-000054']
  tag nist: ['AC-10']

  describe nginx_conf_custom(input('nginx_conf_path')).params['http'][0]['limit_conn'] do
    it { should include ['per_ip', "#{input('limit_conn_ip_limit')}"] }
  end

  describe nginx_conf_custom(input('nginx_conf_path')).params['http'][0]['limit_conn_zone'] do
    it { should include ['$binary_remote_addr', 'zone=per_ip:10m'] }
  end
end
