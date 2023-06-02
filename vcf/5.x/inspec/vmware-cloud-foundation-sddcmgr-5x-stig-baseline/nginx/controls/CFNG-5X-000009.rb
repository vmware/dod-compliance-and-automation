control 'CFNG-5X-000009' do
  title 'The SDDC Manager NGINX service must capture, record, and log all content related to a user session.'
  desc  'The web server must be capable of enabling a setting for troubleshooting, debugging, or forensic gathering purposes which will log all user session information related to the hosted application session. Without the capability to capture, record, and log all content related to a user session, investigations into suspicious user activity would be hampered.'
  desc  'rationale', ''
  desc  'check', "
    At the command line, run the following command:

    # nginx -T 2>&1 | sed -n \"/^http\\s{/,/server\\s{/p\" | grep access_log

    Example result:

    access_log /var/log/nginx/access.log custom;

    If the \"access_log\" is not configured to log to \"/var/log/nginx/access.log\" with a log format of \"custom\", this is a finding.
  "
  desc 'fix', "
    Navigate to and open:

    The nginx.conf (/etc/nginx/nginx.conf by default) file.

    Add the following line in the http context:

    access_log /var/log/nginx/access.log custom;

    At the command line, run the following command:

    # nginx -s reload
  "
  impact 0.5
  tag severity: 'medium'
  tag gtitle: 'SRG-APP-000093-WSR-000053'
  tag gid: 'V-CFNG-5X-000009'
  tag rid: 'SV-CFNG-5X-000009'
  tag stig_id: 'CFNG-5X-000009'
  tag cci: ['CCI-001462']
  tag nist: ['AU-14 (2)']

  nginx_access_log_path = input('nginx_access_log_file')
  nginx_access_log_format_name = input('nginx_access_log_format_name')

  describe nginx_conf_custom(input('nginx_conf_path')).params['http'][0]['access_log'] do
    it { should include [nginx_access_log_path, nginx_access_log_format_name] }
  end
end
