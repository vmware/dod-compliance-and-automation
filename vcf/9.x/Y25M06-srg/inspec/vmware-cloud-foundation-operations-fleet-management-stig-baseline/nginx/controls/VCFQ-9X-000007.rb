control 'VCFQ-9X-000007' do
  title 'The VMware Cloud Foundation Operations Fleet Management NGINX server must generate log records for system events.'
  desc  "
    Log records can be generated from various components within the web server (e.g., httpd, plug-ins to external backends, etc.). From a web server perspective, certain specific web server functionalities may be logged as well. The web server must allow the definition of what events are to be logged. As conditions change, the number and types of events to be logged may change, and the web server must be able to facilitate these changes.

    The minimum list of logged events should be those pertaining to system startup and shutdown, system access, and system authentication events. If these events are not logged at a minimum, any type of forensic investigation would be missing pertinent information needed to replay what occurred.
  "
  desc  'rationale', ''
  desc  'check', "
    View the running configuration by running the following command:

    # nginx -T 2>&1 | grep \"^error_log\"

    Example result:

    error_log /var/log/nginx/error.log info;

    If the output does not include the \"error_log\" directive in the main context and set to at least \"info\", this is a finding.
  "
  desc 'fix', "
    Navigate to and open:

    The nginx.conf (/etc/nginx/nginx.conf by default) file.

    Add the following line in the main context at the top of the file:

    error_log /var/log/nginx/error.log info;

    Reload the NGINX configuration by running the following command:

    # nginx -s reload
  "
  impact 0.5
  tag severity: 'medium'
  tag gtitle: 'SRG-APP-000089-WSR-000047'
  tag satisfies: ['SRG-APP-000092-WSR-000055']
  tag gid: 'V-VCFQ-9X-000007'
  tag rid: 'SV-VCFQ-9X-000007'
  tag stig_id: 'VCFQ-9X-000007'
  tag cci: ['CCI-000169', 'CCI-001464']
  tag nist: ['AU-12 a', 'AU-14 (1)']

  nginx_error_log_path = input('nginx_error_log_file')
  nginx_error_log_level = input('nginx_error_log_level')

  describe 'The error_log directive in the main context' do
    subject { nginx_conf_custom(input('nginx_conf_path')).params['error_log'] }
    it { should include [nginx_error_log_path, nginx_error_log_level] }
  end
end
