control 'VCPF-70-000029' do
  title 'Performance Charts must properly configure log sizes and rotation.'
  desc  "To ensure that the logging mechanism used by the web server has
sufficient storage capacity in which to write the logs, the logging mechanism
needs to be able to allocate log record storage capacity. Performance Charts
properly sizes and configures log rotation during installation. This default
configuration must be verified."
  desc  'rationale', ''
  desc  'check', "
    At the command prompt, execute the following command:

    # rpm -V VMware-perfcharts|grep log4j|grep \"^..5......\"

    If the command returns any output, this is a finding.
  "
  desc 'fix', "
    Navigate to and open:

    /etc/vmware-perfcharts/log4j.properties

    Ensure that the log4j.appender.LOGFILE is configured as follows:


log4j.appender.LOGFILE=com.vmware.log4j.appender.NonAppendingRollingFileAppender
    log4j.appender.LOGFILE.File=${vim.logdir}/stats.log
    log4j.appender.LOGFILE.Append=true
    log4j.appender.LOGFILE.MaxFileSize=5MB
    log4j.appender.LOGFILE.MaxBackupIndex=10
    log4j.appender.LOGFILE.layout=org.apache.log4j.PatternLayout

log4j.appender.LOGFILE.layout.ConversionPattern=%d{yyyy-MM-dd'T'HH:mm:ss.SSSXXX}
[%t %x %-5p %c] %m%n

    Note: This fix is currently only applicable to 7.0 versions earlier than U2.
  "
  impact 0.5
  tag severity: 'medium'
  tag gtitle: 'SRG-APP-000357-WSR-000150'
  tag gid: nil
  tag rid: nil
  tag stig_id: 'VCPF-70-000029'
  tag fix_id: nil
  tag cci: ['CCI-001849']
  tag nist: ['AU-4']

  describe command('rpm -V VMware-perfcharts|grep log4j|grep "^..5......"') do
    its('stdout.strip') { should eq '' }
  end
end
