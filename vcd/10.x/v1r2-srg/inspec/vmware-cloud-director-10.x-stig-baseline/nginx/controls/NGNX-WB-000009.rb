control 'NGNX-WB-000009' do
  title 'NGINX must capture, record, and log all content related to a user session.'
  desc  "
    A user session to a web server is in the context of a user accessing a hosted application that extends to any plug-ins/modules and services that may execute on behalf of the user.

    The web server must be capable of enabling a setting for troubleshooting, debugging, or forensic gathering purposes which will log all user session information related to the hosted application session. Without the capability to capture, record, and log all content related to a user session, investigations into suspicious user activity would be hampered.
  "
  desc  'rationale', ''
  desc  'check', "
    Verify access logging has been enabled in the http block.

    View the running configuration by running the following command:

    # nginx -T

    Example configuration:

    http {
      access_log /var/log/nginx/access.log custom;
    }

    If the access_log directive is not configured in the http block, this is a finding.
  "
  desc 'fix', "
    Navigate to and open:

    The nginx.conf (/etc/nginx/nginx.conf by default) file.

    Add the following or similar in the http block:

    access_log /var/log/nginx/access.log custom;

    Reload the NGINX configuration by running the following command:

    # nginx -s reload
  "
  impact 0.5
  tag severity: 'medium'
  tag gtitle: 'SRG-APP-000093-WSR-000053'
  tag gid: 'V-NGNX-WB-000009'
  tag rid: 'SV-NGNX-WB-000009'
  tag stig_id: 'NGNX-WB-000009'
  tag cci: ['CCI-001462']
  tag nist: ['AU-14 (2)']

  nginx_access_log_path = input('nginx_access_log_file')
  nginx_access_log_format_name = input('nginx_access_log_format_name')

  describe nginx_conf_custom(input('nginx_conf_path')).params['http'][0]['access_log'] do
    it { should include [nginx_access_log_path, nginx_access_log_format_name] }
  end
end
