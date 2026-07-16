control 'VCFB-9X-000009' do
  title 'The VMware Cloud Foundation SDDC Manager NGINX server must capture, record, and log all content related to a user session.'
  desc  "
    A user session to a web server is in the context of a user accessing a hosted application that extends to any plug-ins/modules and services that may execute on behalf of the user.

    The web server must be capable of enabling a setting for troubleshooting, debugging, or forensic gathering purposes which will log all user session information related to the hosted application session. Without the capability to capture, record, and log all content related to a user session, investigations into suspicious user activity would be hampered.
  "
  desc  'rationale', ''
  desc  'check', "
    Verify access logging has been enabled in the http context.

    View the running configuration by running the following command:

    # nginx -T 2>&1 | sed -n \"/^http\\s{/,/server\\s{/p\" | grep access_log

    Example configuration:

    http {
      access_log /var/log/nginx/access.log custom;
    }

    If the access_log directive is not configured in the http context, this is a finding.
  "
  desc 'fix', "
    Navigate to and open:

    The nginx.conf (/etc/nginx/nginx.conf by default) file.

    Add the following or similar in the http context:

    access_log /var/log/nginx/access.log custom;

    Reload the NGINX configuration by running the following command:

    # nginx -s reload
  "
  impact 0.5
  tag severity: 'medium'
  tag gtitle: 'SRG-APP-000093-WSR-000053'
  tag gid: 'V-VCFB-9X-000009'
  tag rid: 'SV-VCFB-9X-000009'
  tag stig_id: 'VCFB-9X-000009'
  tag cci: ['CCI-001462']
  tag nist: ['AU-14 (2)']

  nginx_access_log_path = input('nginx_access_log_file')
  nginx_access_log_format_name = input('nginx_access_log_format_name')

  describe 'The access_log directive in the http context' do
    subject { nginx_conf_custom(input('nginx_conf_path')).params['http'][0]['access_log'] }
    it { should include [nginx_access_log_path, nginx_access_log_format_name] }
  end
end
