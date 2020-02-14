control "VCST-67-000006" do
  title "The Security Token Service must generate log records during java
startup and shutdown."
  desc  "Logging must be started as soon as possible when a service starts and
as late as possible when a service is stopped. Many forms of suspicious actions
can be detected by analyzing logs for unexpected service starts and stops.
Also, by starting to log immediately after a service starts, it becomes more
difficult for suspicous activity to go un-logged."
  impact 0.5
  tag severity: "CAT II"
  tag gtitle: "SRG-APP-000089-WSR-000047"
  tag gid: nil
  tag rid: "VCST-67-000006"
  tag stig_id: "VCST-67-000006"
  tag cci: "CCI-000169"
  tag nist: ["AU-12 a", "Rev_4"]
  desc 'check', "At the command prompt, execute the following command:

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

If the output does not match the expected result, this is a finding."
  desc 'fix', "Navigate to and open
/usr/lib/vmware-sso/vmware-sts/conf/logging.properties .

Ensure that the 'handlers' and '.handlers' lines are configured as below:

handlers = 1catalina.org.apache.juli.FileHandler,
2localhost.org.apache.juli.FileHandler, 3manager.org.apache.juli.FileHandler,
4host-manager.org.apache.juli.FileHandler, java.util.logging.ConsoleHandler

.handlers = 1catalina.org.apache.juli.FileHandler

Ensure that the following lines are present:

1catalina.org.apache.juli.FileHandler.level = FINE
1catalina.org.apache.juli.FileHandler.directory = ${catalina.base}/logs
1catalina.org.apache.juli.FileHandler.prefix = catalina.
1catalina.org.apache.juli.FileHandler.bufferSize = -1"

  describe parse_config_file('/usr/lib/vmware-sso/vmware-sts/conf/logging.properties').params['handlers'] do
    it { should eq '1catalina.org.apache.juli.FileHandler, 2localhost.org.apache.juli.FileHandler, 3manager.org.apache.juli.FileHandler, 4host-manager.org.apache.juli.FileHandler, java.util.logging.ConsoleHandler' }
  end

  describe parse_config_file('/usr/lib/vmware-sso/vmware-sts/conf/logging.properties').params['.handlers'] do
    it { should eq '1catalina.org.apache.juli.FileHandler' }
  end

  describe parse_config_file('/usr/lib/vmware-sso/vmware-sts/conf/logging.properties').params['1catalina.org.apache.juli.FileHandler.level'] do
    it { should eq 'FINE' }
  end

  describe parse_config_file('/usr/lib/vmware-sso/vmware-sts/conf/logging.properties').params['1catalina.org.apache.juli.FileHandler.directory'] do
    it { should eq '${catalina.base}/logs' }
  end

  describe parse_config_file('/usr/lib/vmware-sso/vmware-sts/conf/logging.properties').params['1catalina.org.apache.juli.FileHandler.prefix'] do
    it { should eq 'catalina.' }
  end

  describe parse_config_file('/usr/lib/vmware-sso/vmware-sts/conf/logging.properties').params['1catalina.org.apache.juli.FileHandler.bufferSize'] do
    it { should eq '-1' }
  end

end