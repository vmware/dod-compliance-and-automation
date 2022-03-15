control 'VCPF-67-000026' do
  title 'Performance Charts must properly configure log sizes and rotation.'
  desc  "To ensure that the logging mechanism used by the web server has
sufficient storage capacity in which to write the logs, the logging mechanism
must be able to allocate log record storage capacity. Performance Charts
properly sizes and configures log rotation during installation. This default
configuration must be verified."
  desc  'rationale', ''
  desc  'check', "
    At the command prompt, execute the following command:

    # grep -i \"max\" /etc/vmware-perfcharts/log4j.properties

    Expected result:

    log4j.appender.LOGFILE.MaxFileSize=5MB
    log4j.appender.LOGFILE.MaxBackupIndex=10

    If the output of the command does not match the expected result, this is a
finding.
  "
  desc 'fix', "
    Open  /etc/vmware-perfcharts/log4j.properties with a text editor and add or
change the following settings:

    log4j.appender.LOGFILE.MaxFileSize=5MB
    log4j.appender.LOGFILE.MaxBackupIndex=10
  "
  impact 0.5
  tag severity: 'medium'
  tag gtitle: 'SRG-APP-000357-WSR-000150'
  tag gid: 'V-239427'
  tag rid: 'SV-239427r675004_rule'
  tag stig_id: 'VCPF-67-000026'
  tag fix_id: 'F-42619r675003_fix'
  tag cci: ['CCI-001849']
  tag nist: ['AU-4']

  describe parse_config_file('/etc/vmware-perfcharts/log4j.properties').params['log4j.appender.LOGFILE.MaxFileSize'] do
    it { should eq '5MB' }
  end

  describe parse_config_file('/etc/vmware-perfcharts/log4j.properties').params['log4j.appender.LOGFILE.MaxBackupIndex'] do
    it { should eq '10' }
  end
end
