control 'VCST-70-000006' do
  title 'The Security Token Service must generate log records during Java startup and shutdown.'
  desc 'Logging must be started as soon as possible when a service starts and as late as possible when a service is stopped. Many forms of suspicious actions can be detected by analyzing logs for unexpected service starts and stops. Also, by starting to log immediately after a service starts, it becomes more difficult for suspicious activity to go unlogged.

'
  desc 'check', 'At the command prompt, run the following command:

# grep "1catalina.org.apache.juli.FileHandler" /usr/lib/vmware-sso/vmware-sts/conf/logging.properties

Expected result:

handlers = 1catalina.org.apache.juli.FileHandler, 2localhost.org.apache.juli.FileHandler, 3manager.org.apache.juli.FileHandler, 4host-manager.org.apache.juli.FileHandler
.handlers = 1catalina.org.apache.juli.FileHandler
1catalina.org.apache.juli.FileHandler.level = FINE
1catalina.org.apache.juli.FileHandler.directory = ${catalina.base}/logs/tomcat
1catalina.org.apache.juli.FileHandler.prefix = catalina.
1catalina.org.apache.juli.FileHandler.bufferSize = -1
1catalina.org.apache.juli.FileHandler.formatter = java.util.logging.SimpleFormatter
1catalina.org.apache.juli.FileHandler.maxDays = 10
org.apache.catalina.startup.Catalina.handlers = 1catalina.org.apache.juli.FileHandler

If the output does not match the expected result, this is a finding.'
  desc 'fix', 'Navigate to and open:

/usr/lib/vmware-sso/vmware-sts/conf/logging.properties

Ensure that the "handlers" and ".handlers" lines are configured as follows:

handlers = 1catalina.org.apache.juli.FileHandler, 2localhost.org.apache.juli.FileHandler, 3manager.org.apache.juli.FileHandler, 4host-manager.org.apache.juli.FileHandler
.handlers = 1catalina.org.apache.juli.FileHandler
1catalina.org.apache.juli.FileHandler.level = FINE
1catalina.org.apache.juli.FileHandler.directory = ${catalina.base}/logs/tomcat
1catalina.org.apache.juli.FileHandler.prefix = catalina.
1catalina.org.apache.juli.FileHandler.bufferSize = -1
1catalina.org.apache.juli.FileHandler.formatter = java.util.logging.SimpleFormatter
1catalina.org.apache.juli.FileHandler.maxDays = 10
org.apache.catalina.startup.Catalina.handlers = 1catalina.org.apache.juli.FileHandler

Restart the service with the following command:

# vmon-cli --restart sts'
  impact 0.5
  tag check_id: 'C-60425r918972_chk'
  tag severity: 'medium'
  tag gid: 'V-256750'
  tag rid: 'SV-256750r918974_rule'
  tag stig_id: 'VCST-70-000006'
  tag gtitle: 'SRG-APP-000089-WSR-000047'
  tag fix_id: 'F-60368r918973_fix'
  tag satisfies: ['SRG-APP-000089-WSR-000047', 'SRG-APP-000092-WSR-000055']
  tag cci: ['CCI-000169', 'CCI-001464']
  tag nist: ['AU-12 a', 'AU-14 (1)']

  describe parse_config_file("#{input('loggingProperties')}").params['handlers'] do
    it { should eq '1catalina.org.apache.juli.FileHandler, 2localhost.org.apache.juli.FileHandler, 3manager.org.apache.juli.FileHandler, 4host-manager.org.apache.juli.FileHandler' }
  end

  describe parse_config_file("#{input('loggingProperties')}").params['.handlers'] do
    it { should eq '1catalina.org.apache.juli.FileHandler' }
  end

  describe parse_config_file("#{input('loggingProperties')}").params['1catalina.org.apache.juli.FileHandler.level'] do
    it { should eq 'FINE' }
  end

  describe parse_config_file("#{input('loggingProperties')}").params['1catalina.org.apache.juli.FileHandler.directory'] do
    it { should eq '${catalina.base}/logs/tomcat' }
  end

  describe parse_config_file("#{input('loggingProperties')}").params['1catalina.org.apache.juli.FileHandler.prefix'] do
    it { should eq 'catalina.' }
  end

  describe parse_config_file("#{input('loggingProperties')}").params['1catalina.org.apache.juli.FileHandler.bufferSize'] do
    it { should eq '-1' }
  end

  describe parse_config_file("#{input('loggingProperties')}").params['1catalina.org.apache.juli.FileHandler.formatter'] do
    it { should eq 'java.util.logging.SimpleFormatter' }
  end

  describe parse_config_file("#{input('loggingProperties')}").params['1catalina.org.apache.juli.FileHandler.maxDays'] do
    it { should eq '10' }
  end

  describe parse_config_file("#{input('loggingProperties')}").params['org.apache.catalina.startup.Catalina.handlers'] do
    it { should eq '1catalina.org.apache.juli.FileHandler' }
  end
end
