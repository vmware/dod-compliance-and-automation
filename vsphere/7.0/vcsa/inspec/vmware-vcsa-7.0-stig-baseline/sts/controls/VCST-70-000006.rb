# encoding: UTF-8

control 'VCST-70-000006' do
  title "The Security Token Service must generate log records during java
startup and shutdown."
  desc  "Logging must be started as soon as possible when a service starts and
as late as possible when a service is stopped. Many forms of suspicious actions
can be detected by analyzing logs for unexpected service starts and stops.
Also, by starting to log immediately after a service starts, it becomes more
difficult for suspicous activity to go un-logged."
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
    Navigate to and open /usr/lib/vmware-sso/vmware-sts/conf/logging.properties
.

    Ensure that the 'handlers' and '.handlers' lines are configured as below:

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


  
end

