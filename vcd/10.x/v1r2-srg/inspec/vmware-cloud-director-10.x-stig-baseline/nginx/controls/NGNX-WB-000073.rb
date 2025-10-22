control 'NGNX-WB-000073' do
  title 'NGINX must send logs to a centralized log server.'
  desc  'Writing events to a centralized management audit system offers many benefits to the enterprise over having dispersed logs. Centralized management of audit records and logs provides for efficiency in maintenance and management of records, enterprise analysis of events, and backup and archiving of event records enterprise-wide. The web server and related components are required to be capable of writing logs to centralized audit log servers.'
  desc  'rationale', ''
  desc  'check', "
    Verify syslog has been configured for error and access logs.

    View the running configuration by running the following command:

    # nginx -T

    Example configuration:

    error_log syslog:server=10.10.10.10:514 info;

    http {
      access_log syslog:server=10.10.10.10:514,severity=info  custom;
    }

    If access and error logs are not configured to send events to a syslog server, this is a finding.

    If access and error logs are configured to send events to a syslog server via another method such as configuring rsyslog to monitor the log files, this is NOT a finding.

    Note: These log directives are in addition to the configurations that log to files for access and error logs.
  "
  desc 'fix', "
    Navigate to and open:

    The nginx.conf (/etc/nginx/nginx.conf by default) file.

    Add or update the following line in the http block and replace the syslog server destination and port for an approved log server in your environment:

    access_log syslog:server=10.10.10.10:514,severity=info  custom;

    Add or update the following line in the main context and replace the syslog server destination and port for an approved log server in your environment::

    error_log syslog:server=10.10.10.10:514 info;

    Reload the NGINX configuration by running the following command:

    # nginx -s reload

    Note: Do not remove the access_log and error_log entries configured to log directly to a file.
  "
  impact 0.5
  tag severity: 'medium'
  tag gtitle: 'SRG-APP-000358-WSR-000063'
  tag satisfies: ['SRG-APP-000358-WSR-000163']
  tag gid: 'V-NGNX-WB-000073'
  tag rid: 'SV-NGNX-WB-000073'
  tag stig_id: 'NGNX-WB-000073'
  tag cci: ['CCI-001851']
  tag nist: ['AU-4 (1)']

  nginx_syslog_enabled = input('nginx_syslog_enabled')
  nginx_syslog_server_error = input('nginx_syslog_server_error')
  nginx_error_log_level = input('nginx_error_log_level')
  nginx_syslog_server_access = input('nginx_syslog_server_access')
  nginx_access_log_format_name = input('nginx_access_log_format_name')

  if nginx_syslog_enabled == true
    # Check error log
    describe nginx_conf_custom(input('nginx_conf_path')).params['error_log'] do
      it { should include [nginx_syslog_server_error, nginx_error_log_level] }
    end
    describe nginx_conf_custom(input('nginx_conf_path')).params['http'][0]['access_log'] do
      it { should include [nginx_syslog_server_access, nginx_access_log_format_name] }
    end
  else
    describe 'Logs shipping done outside of NGINX...' do
      skip 'Logs shipping done outside of NGINX...skipping...'
    end
  end
end
