control 'CFNG-4X-000008' do
  title 'The SDDC Manager NGINX service must log server events upon start up.'
  desc  'An attacker can compromise a web server during the startup process. If logging is not initiated until all the web server processes are started, key information may be missed and not available during a forensic investigation. To assure all logable events are captured, the web server must begin logging once the first web server process is initiated.'
  desc  'rationale', ''
  desc  'check', "
    At the command line, run the following command:

    # nginx -T 2>&1 | grep \"^error_log\"

    Expected result:

    error_log /var/log/nginx/error.log info;

    If the output does not match the expected result, this is a finding.
  "
  desc 'fix', "
    Navigate to and open:

    The nginx.conf (/etc/nginx/nginx.conf by default) file.

    Add the following line in the main context at the top of the file:

    error_log /var/log/nginx/error.log info;

    At the command line, run the following command:

    # nginx -s reload
  "
  impact 0.5
  tag severity: 'medium'
  tag gtitle: 'SRG-APP-000092-WSR-000055'
  tag gid: 'V-CFNG-4X-000008'
  tag rid: 'SV-CFNG-4X-000008'
  tag stig_id: 'CFNG-4X-000008'
  tag cci: ['CCI-001464']
  tag nist: ['AU-14 (1)']

  nginx_error_log_path = input('nginx_error_log_file')

  describe nginx_conf_custom(input('nginx_conf_path')).params['error_log'] do
    it { should include [nginx_error_log_path, 'info'] }
  end
end
