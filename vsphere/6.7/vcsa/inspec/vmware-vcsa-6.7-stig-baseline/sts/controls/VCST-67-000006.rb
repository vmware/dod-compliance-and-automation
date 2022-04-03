control 'VCST-67-000006' do
  title "The Security Token Service must generate log records during Java
startup and shutdown."
  desc  "Logging must be started as soon as possible when a service starts and
as late as possible when a service is stopped. Many forms of suspicious actions
can be detected by analyzing logs for unexpected service starts and stops.
Also, by starting to log immediately after a service starts, it becomes more
difficult for suspicious activity to go unlogged."
  desc  'rationale', ''
  desc  'check', "
    Connect to the PSC, whether external or embedded.

    At the command prompt, execute the following command:

    # grep \"1catalina.org.apache.juli.FileHandler\"
/usr/lib/vmware-sso/vmware-sts/conf/logging.properties

    Expected result:

    handlers = 1catalina.org.apache.juli.FileHandler,
2localhost.org.apache.juli.FileHandler, 3manager.org.apache.juli.FileHandler,
4host-manager.org.apache.juli.FileHandler, java.util.logging.ConsoleHandler
    .handlers = 1catalina.org.apache.juli.FileHandler
    1catalina.org.apache.juli.FileHandler.level = FINE
    1catalina.org.apache.juli.FileHandler.directory = ${catalina.base}/logs
    1catalina.org.apache.juli.FileHandler.prefix = catalina.
    1catalina.org.apache.juli.FileHandler.bufferSize = -1

    If the output does not match the expected result, this is a finding.
  "
  desc 'fix', "
    Connect to the PSC, whether external or embedded.

    Navigate to and open /usr/lib/vmware-sso/vmware-sts/conf/logging.properties.

    Ensure that the \"handlers\" and \".handlers\" lines are configured as
follows:

    handlers = 1catalina.org.apache.juli.FileHandler,
2localhost.org.apache.juli.FileHandler, 3manager.org.apache.juli.FileHandler,
4host-manager.org.apache.juli.FileHandler, java.util.logging.ConsoleHandler

    .handlers = 1catalina.org.apache.juli.FileHandler

    Ensure that the following lines are present:

    1catalina.org.apache.juli.FileHandler.level = FINE
    1catalina.org.apache.juli.FileHandler.directory = ${catalina.base}/logs
    1catalina.org.apache.juli.FileHandler.prefix = catalina.
    1catalina.org.apache.juli.FileHandler.bufferSize = -1
  "
  impact 0.5
  tag severity: 'medium'
  tag gtitle: 'SRG-APP-000089-WSR-000047'
  tag gid: 'V-239657'
  tag rid: 'SV-239657r816696_rule'
  tag stig_id: 'VCST-67-000006'
  tag fix_id: 'F-42849r816695_fix'
  tag cci: ['CCI-000169']
  tag nist: ['AU-12 a']

  describe parse_config_file("#{input('loggingProperties')}").params['handlers'] do
    it { should eq '1catalina.org.apache.juli.FileHandler, 2localhost.org.apache.juli.FileHandler, 3manager.org.apache.juli.FileHandler, 4host-manager.org.apache.juli.FileHandler, java.util.logging.ConsoleHandler' }
  end

  describe parse_config_file("#{input('loggingProperties')}").params['.handlers'] do
    it { should eq '1catalina.org.apache.juli.FileHandler' }
  end

  describe parse_config_file("#{input('loggingProperties')}").params['1catalina.org.apache.juli.FileHandler.level'] do
    it { should eq 'FINE' }
  end

  describe parse_config_file("#{input('loggingProperties')}").params['1catalina.org.apache.juli.FileHandler.directory'] do
    it { should eq '${catalina.base}/logs' }
  end

  describe parse_config_file("#{input('loggingProperties')}").params['1catalina.org.apache.juli.FileHandler.prefix'] do
    it { should eq 'catalina.' }
  end

  describe parse_config_file("#{input('loggingProperties')}").params['1catalina.org.apache.juli.FileHandler.bufferSize'] do
    it { should eq '-1' }
  end
end
