control 'VCFB-9X-000001' do
  title 'The VMware Cloud Foundation SDDC Manager NGINX server must limit the number of concurrent connections per server.'
  desc  "
    Web server management includes the ability to control the number of users and user sessions that utilize a web server. Limiting the number of allowed users and sessions per user is helpful in limiting risks related to several types of Denial of Service attacks.

    Although there is some latitude concerning the settings themselves, the settings should follow DOD-recommended values, but the settings should be configurable to allow for future DOD direction. While the DOD will specify recommended values, the values can be adjusted to accommodate the operational requirement of a given system.
  "
  desc  'rationale', ''
  desc  'check', "
    Verify a shared memory zone has been established in the http context to track connections per server.

    View the running configuration by running the following command:

    # nginx -T 2>&1 | sed -n \"/^http\\s{/,/server\\s{/p\" | grep limit_conn

    Example configuration:

    http {
      limit_conn_zone $server_name zone=per_server:10m;
      limit_conn per_server 1000;
    }

    If the \"limit_conn_zone\" directive is not configured in the http context to limit connections per server, this is a finding.

    If the \"limit_conn\" directive is not configured in the http context to limit connections per server, this is a finding.

    Note: \"limit_conn\" directives under server or location contexts are acceptable to modify limits based on application needs as long as they are not disabled.
  "
  desc 'fix', "
    Navigate to and open:

    The nginx.conf (/etc/nginx/nginx.conf by default) file.

    Add the following or similar line(s) in the http context:

    limit_conn_zone $server_name zone=per_server:10m;
    limit_conn per_server 1000;

    Reload the NGINX configuration by running the following command:

    # nginx -s reload
  "
  impact 0.5
  tag severity: 'medium'
  tag gtitle: 'SRG-APP-000001-WSR-000001'
  tag gid: 'V-VCFB-9X-000001'
  tag rid: 'SV-VCFB-9X-000001'
  tag stig_id: 'VCFB-9X-000001'
  tag cci: ['CCI-000054']
  tag nist: ['AC-10']

  limit_conn_zone = nginx_conf_custom(input('nginx_conf_path')).params['http'][0]['limit_conn_zone']
  limit_conn = nginx_conf_custom(input('nginx_conf_path')).params['http'][0]['limit_conn']

  if limit_conn_zone
    describe 'The limit_conn_zone directive in the http context' do
      subject { limit_conn_zone }
      it { should include ['$server_name', 'zone=per_server:10m'] }
    end
    describe 'The limit_conn directive in the http context' do
      subject { limit_conn }
      it { should include ['per_server', "#{input('limit_conn_server_limit')}"] }
    end
  else
    describe 'The limit_conn_zone directive in the http context' do
      subject { limit_conn_zone }
      it { should_not be nil }
    end
    describe 'The limit_conn directive in the http context' do
      subject { limit_conn }
      it { should_not be nil }
    end
  end
end
