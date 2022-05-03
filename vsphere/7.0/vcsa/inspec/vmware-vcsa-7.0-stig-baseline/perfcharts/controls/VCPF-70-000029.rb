control 'VCPF-70-000029' do
  title 'Performance Charts must properly configure log sizes and rotation.'
  desc  'To ensure that the logging mechanism used by the web server has sufficient storage capacity in which to write the logs, the logging mechanism needs to be able to allocate log record storage capacity. Performance Charts properly sizes and configures log rotation during installation. This default configuration must be verified.'
  desc  'rationale', ''
  desc  'check', "
    At the command prompt, execute the following command:

    # rpm -V VMware-perfcharts|grep log4j|grep \"^..5......\"

    If the command returns any output, this is a finding.
  "
  desc 'fix', "
    Navigate to and open:

    /etc/vmware-perfcharts/log4j.properties

    Ensure that the appender.rolling entries are configured as follows:

    appender.rolling.type = RollingFile
    appender.rolling.name = FileLog
    appender.rolling.fileName = /var/log/vmware/perfcharts/stats.log
    appender.rolling.filePattern = /var/log/vmware/perfcharts/stats-%i.log
    appender.rolling.policies.type = Policies
    appender.rolling.policies.size.type = SizeBasedTriggeringPolicy
    appender.rolling.policies.size.size = 5MB
    appender.rolling.strategy.type = DefaultRolloverStrategy
    appender.rolling.strategy.max = 10
    appender.rolling.layout.type = PatternLayout
    appender.rolling.layout.pattern = %d{yyyy-MM-dd'T'HH:mm:ss.SSSXXX} [%t %-5p %c] %m%n
    appender.rolling.level = info

    Note: This fix is currently only applicable to 7.0 U2+ and is different in older versions.
  "
  impact 0.5
  tag severity: 'medium'
  tag gtitle: 'SRG-APP-000357-WSR-000150'
  tag gid: nil
  tag rid: nil
  tag stig_id: 'VCPF-70-000029'
  tag cci: ['CCI-001849']
  tag nist: ['AU-4']

  describe command('rpm -V VMware-perfcharts|grep log4j|grep "^..5......"') do
    its('stdout.strip') { should eq '' }
  end
end
