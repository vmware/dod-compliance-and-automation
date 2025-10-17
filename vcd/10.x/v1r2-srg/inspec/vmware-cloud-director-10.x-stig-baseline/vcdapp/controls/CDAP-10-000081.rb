control 'CDAP-10-000081' do
  title 'Cloud Director must off-load log records to a centralized logging server.'
  desc  "
    Information system logging capability is critical for accurate forensic analysis. Log record content that may be necessary to satisfy the requirement of this control includes, but is not limited to, time stamps, source and destination IP addresses, user/process identifiers, event descriptions, application-specific events, success/fail indications, filenames involved, access control or flow control rules invoked.

    Off-loading is a common process in information systems with limited log storage capacity.

    Centralized management of log records provides for efficiency in maintenance and management of records, as well as the backup and archiving of those records. Application servers and their related components are required to off-load log records onto a different system or media than the system being logged.
  "
  desc  'rationale', ''
  desc  'check', "
    In Cloud Director, there are two types of logs that a system administrator can configure to ship via syslog.

    Audit log messages - These are the Audit Messages which are stored in the Cloud Director database and retained by default for 90 days.

    Diagnostic log files - These are the log files present in the /opt/vmware/vcloud-director/logs directory of the Cloud Director Cells.

    Audit log and diagnostic log shipping are configured separately and must both be checked.

    Verify syslog is configured for audit events by running the following command on each appliance:

    # grep audit.syslog /opt/vmware/vcloud-director/etc/global.properties

    Example output:

    audit.syslog.host = 10.10.10.10
    audit.syslog.port = 514

    If an authorized audit syslog host is not specified, this is a finding.

    Verify syslog is configured for diagnostic logs by running the following command on each appliance:

    # grep 'log4j.rootLogger\\|log4j.appender.vcloud.system.syslog' /opt/vmware/vcloud-director/etc/log4j.properties

    Example output:

    log4j.rootLogger=ERROR, vcloud.system.debug, vcloud.system.info, vcloud.system.syslog
    log4j.appender.vcloud.system.syslog=org.apache.log4j.net.SyslogAppender
    log4j.appender.vcloud.system.syslog.syslogHost=10.10.10.10:514
    log4j.appender.vcloud.system.syslog.facility=LOCAL1
    log4j.appender.vcloud.system.syslog.layout=com.vmware.vcloud.logging.layout.CustomPatternLayout
    log4j.appender.vcloud.system.syslog.layout.ConversionPattern=%d{ISO8601} | %-8.8p | %-25.50t | %-30.50c{1} | %m | %x%n
    log4j.appender.vcloud.system.syslog.threshold=INFO

  "
  desc 'fix', "
    To configure audit logs to be sent to a syslog server, execute the following command:

    # /opt/vmware/vcloud-director/bin/cell-management-tool configure-audit-syslog -loghost <IP/FQDN> -logport <Port>

    To configure diagnostic logs to be sent to a syslog server, perform the following steps:

    Navigate to and open:

    /opt/vmware/vcloud-director/etc/log4j.properties

    Update the log4j.rootLogger line to add a syslog logger, for example:

    log4j.rootLogger=ERROR, vcloud.system.debug, vcloud.system.info, vcloud.system.syslog

    Add a new section at the end of the file for the new syslog configuration, for example:

    log4j.appender.vcloud.system.syslog=org.apache.log4j.net.SyslogAppender
    log4j.appender.vcloud.system.syslog.syslogHost=10.10.10.10:514
    log4j.appender.vcloud.system.syslog.facility=LOCAL1
    log4j.appender.vcloud.system.syslog.layout=com.vmware.vcloud.logging.layout.CustomPatternLayout
    log4j.appender.vcloud.system.syslog.layout.ConversionPattern=%d{ISO8601} | %-8.8p | %-25.50t | %-30.50c{1} | %m | %x%n
    log4j.appender.vcloud.system.syslog.threshold=INFO

    Note: Update the syslogHost line with your syslog server IP/FQDN and Port information.

    Note: It is recommended to take a backup of the log4j.properties before editing.

    Repeat the steps above for each Cloud Director appliance.
  "
  impact 0.5
  tag severity: 'medium'
  tag gtitle: 'SRG-APP-000358-AS-000064'
  tag satisfies: ['SRG-APP-000515-AS-000203']
  tag gid: 'V-CDAP-10-000081'
  tag rid: 'SV-CDAP-10-000081'
  tag stig_id: 'CDAP-10-000081'
  tag cci: ['CCI-001851']
  tag nist: ['AU-4 (1)']

  describe parse_config_file('/opt/vmware/vcloud-director/etc/global.properties') do
    its(['audit.syslog.host']) { should cmp "#{input('syslogHost')}" }
    its(['audit.syslog.port']) { should cmp "#{input('syslogPort')}" }
  end
  describe parse_config_file('/opt/vmware/vcloud-director/etc/log4j.properties') do
    its(['log4j.rootLogger']) { should match /vcloud\.system\.syslog/ }
    its(['log4j.appender.vcloud.system.syslog']) { should cmp 'org.apache.log4j.net.SyslogAppender' }
    its(['log4j.appender.vcloud.system.syslog.syslogHost']) { should cmp "#{input('syslogHost')}:#{input('syslogPort')}" }
    its(['log4j.appender.vcloud.system.syslog.facility']) { should cmp 'LOCAL1' }
    its(['log4j.appender.vcloud.system.syslog.layout']) { should cmp 'com.vmware.vcloud.logging.layout.CustomPatternLayout' }
    its(['log4j.appender.vcloud.system.syslog.layout.ConversionPattern']) { should cmp '%d{ISO8601} | %-8.8p | %-25.50t | %-30.50c{1} | %m | %x%n' }
    its(['log4j.appender.vcloud.system.syslog.threshold']) { should cmp 'INFO' }
  end
end
