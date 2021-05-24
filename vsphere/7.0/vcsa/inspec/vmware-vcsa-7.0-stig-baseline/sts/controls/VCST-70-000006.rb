# encoding: UTF-8

control 'VCST-70-000006' do
  title "The Security Token Service must generate log records during Java
startup and shutdown."
  desc  "Log data is essential in the investigation of events. The accuracy of
the information is always pertinent. One of the first steps an attacker will
undertake is the modification or deletion of log records to cover tracks and
prolong discovery.

    The web server must protect the log data from unauthorized modification.
Security Token Service restricts all modification of log files by default, but
this configuration must be verified.
  "
  desc  'rationale', ''
  desc  'check', "
    At the command prompt, execute the following command:

    # grep \"1catalina.org.apache.juli.FileHandler\"
/usr/lib/vmware-sso/vmware-sts/conf/logging.properties

    Expected result:

    handlers = 1catalina.org.apache.juli.FileHandler,
2localhost.org.apache.juli.FileHandler, 3manager.org.apache.juli.FileHandler,
4host-manager.org.apache.juli.FileHandler
    .handlers = 1catalina.org.apache.juli.FileHandler
    1catalina.org.apache.juli.FileHandler.level = FINE
    1catalina.org.apache.juli.FileHandler.directory =
${catalina.base}/logs/tomcat
    1catalina.org.apache.juli.FileHandler.prefix = catalina.
    1catalina.org.apache.juli.FileHandler.bufferSize = -1
    1catalina.org.apache.juli.FileHandler.formatter =
java.util.logging.SimpleFormatter
    org.apache.catalina.startup.Catalina.handlers =
1catalina.org.apache.juli.FileHandler

    If the output does not match the expected result, this is a finding.
  "
  desc  'fix', "
    Navigate to and open:

    /usr/lib/vmware-sso/vmware-sts/conf/logging.properties

    Ensure that the 'handlers' and '.handlers' lines are configured as follows:

    handlers = 1catalina.org.apache.juli.FileHandler,
2localhost.org.apache.juli.FileHandler, 3manager.org.apache.juli.FileHandler,
4host-manager.org.apache.juli.FileHandler
    .handlers = 1catalina.org.apache.juli.FileHandler
    1catalina.org.apache.juli.FileHandler.level = FINE
    1catalina.org.apache.juli.FileHandler.directory =
${catalina.base}/logs/tomcat
    1catalina.org.apache.juli.FileHandler.prefix = catalina.
    1catalina.org.apache.juli.FileHandler.bufferSize = -1
    1catalina.org.apache.juli.FileHandler.formatter =
java.util.logging.SimpleFormatter
    org.apache.catalina.startup.Catalina.handlers =
1catalina.org.apache.juli.FileHandler
  "
  impact 0.5
  tag severity: 'medium'
  tag gtitle: 'SRG-APP-000089-WSR-000047'
  tag gid: nil
  tag rid: nil
  tag stig_id: 'VCST-70-000006'
  tag fix_id: nil
  tag cci: 'CCI-000169'
  tag nist: ['AU-12 a']

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

  describe parse_config_file("#{input('loggingProperties')}").params['org.apache.catalina.startup.Catalina.handlers'] do
    it { should eq '1catalina.org.apache.juli.FileHandler' }
  end
  
end

