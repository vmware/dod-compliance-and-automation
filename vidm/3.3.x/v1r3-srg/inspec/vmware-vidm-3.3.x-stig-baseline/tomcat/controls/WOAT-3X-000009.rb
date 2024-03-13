control 'WOAT-3X-000009' do
  title 'Workspace ONE Access must generate log records for system startup and shutdown.'
  desc  'Logging must be started as soon as possible when a service starts and as late as possible when a service is stopped. Many forms of suspicious actions can be detected by analyzing logs for unexpected service starts and stops. Also, by starting to log immediately after a service starts, it becomes more difficult for suspicous activity to go un-logged.'
  desc  'rationale', ''
  desc  'check', "
    At the command prompt, execute the following command:

    # grep -E \"1catalina|startup\" /opt/vmware/horizon/workspace/conf/logging.properties

    Expected output:

    handlers = 1catalina.java.util.logging.FileHandler, 2localhost.java.util.logging.FileHandler, java.util.logging.ConsoleHandler
    .handlers = 1catalina.java.util.logging.FileHandler, java.util.logging.ConsoleHandler
    1catalina.java.util.logging.FileHandler.level = FINE
    1catalina.java.util.logging.FileHandler.pattern = ${catalina.base}/logs/catalina.log
    1catalina.java.util.logging.FileHandler.limit = 2000000
    1catalina.java.util.logging.FileHandler.count = 1
    1catalina.java.util.logging.FileHandler.formatter = java.util.logging.SimpleFormatter
    org.apache.catalina.startup.Catalina.level = INFO
    org.apache.catalina.startup.Catalina.handlers = 1catalina.java.util.logging.FileHandler

    If the output does not match the expected result, this is a finding.
  "
  desc 'fix', "
    Navigate to and open:

    /opt/vmware/horizon/workspace/conf/logging.properties

    Ensure that the startup events are captured:

    org.apache.catalina.startup.Catalina.level = INFO
    org.apache.catalina.startup.Catalina.handlers = 1catalina.java.util.logging.FileHandler

    Ensure that the logging handler is configured correctly:

    1catalina.java.util.logging.FileHandler.level = FINE
    1catalina.java.util.logging.FileHandler.pattern = ${catalina.base}/logs/catalina.log
    1catalina.java.util.logging.FileHandler.limit = 2000000
    1catalina.java.util.logging.FileHandler.count = 1
    1catalina.java.util.logging.FileHandler.formatter = java.util.logging.SimpleFormatter

    Ensure that the logging handler is registered:

    handlers = 1catalina.java.util.logging.FileHandler, 2localhost.java.util.logging.FileHandler, java.util.logging.ConsoleHandler
    .handlers = 1catalina.java.util.logging.FileHandler, java.util.logging.ConsoleHandler

    Restart the service for changes to take effect by running the following command:

    # systemctl restart horizon-workspace
  "
  impact 0.5
  tag severity: 'medium'
  tag gtitle: 'SRG-APP-000089-WSR-000047'
  tag satisfies: ['SRG-APP-000092-WSR-000055']
  tag gid: 'V-WOAT-3X-000009'
  tag rid: 'SV-WOAT-3X-000009'
  tag stig_id: 'WOAT-3X-000009'
  tag cci: ['CCI-000169', 'CCI-001464']
  tag nist: ['AU-12 a', 'AU-14 (1)']

  describe parse_config_file("#{input('loggingPropertiesPath')}") do
    its('handlers') { should cmp '1catalina.java.util.logging.FileHandler, 2localhost.java.util.logging.FileHandler, java.util.logging.ConsoleHandler' }
    its(['.handlers']) { should cmp '1catalina.java.util.logging.FileHandler, java.util.logging.ConsoleHandler' }
    its(['1catalina.java.util.logging.FileHandler.level']) { should cmp 'FINE' }
    its(['1catalina.java.util.logging.FileHandler.pattern']) { should cmp '${catalina.base}/logs/catalina.log' }
    its(['1catalina.java.util.logging.FileHandler.limit']) { should cmp '2000000' }
    its(['1catalina.java.util.logging.FileHandler.count']) { should cmp '1' }
    its(['1catalina.java.util.logging.FileHandler.formatter']) { should cmp 'java.util.logging.SimpleFormatter' }
    its(['org.apache.catalina.startup.Catalina.level']) { should cmp 'INFO' }
    its(['org.apache.catalina.startup.Catalina.handlers']) { should cmp '1catalina.java.util.logging.FileHandler' }
  end
end
