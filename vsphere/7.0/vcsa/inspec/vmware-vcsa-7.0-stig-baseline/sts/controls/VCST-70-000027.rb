# encoding: UTF-8

control 'VCST-70-000027' do
  title "Rsyslog must be configured to monitor and ship Security Token Service
log files."
  desc  "Web servers provide numerous processes, features, and functionalities
that utilize TCP/IP ports. Some of these processes may be deemed unnecessary or
too unsecure to run on a production system. The ports that the Security Token
Service listens on are configured in the catalina.properties file and must be
veriified as accurate to their shipping state."
  desc  'rationale', ''
  desc  'check', "
    At the command prompt, execute the following command:

    # rpm -V VMware-visl-integration|grep
vmware-services-sso-services.conf|grep \"^..5......\"

    If the command returns any output, this is a finding.
  "
  desc  'fix', "
    Navigate to and open:

    /etc/vmware-syslog/vmware-services-sso-services.conf

    Create the file if it does not exist.

    Set the contents of the file as follows:

    #vmidentity logs
    input(type=\"imfile\"
          File=\"/var/log/vmware/sso/activedirectoryservice.log\"
          Tag=\"activedirectoryservice\"
          PersistStateInterval=\"200\"
          Severity=\"info\"

startmsg.regex=\"^[[:digit:]]{4}-[[:digit:]]{1,2}-[[:digit:]]{1,2}T[[:digit:]]{1,2}:[[:digit:]]{1,2}:[[:digit:]]{1,2}.[[:digit:]]{0,3}Z\"
          Facility=\"local0\")
    input(type=\"imfile\"
          File=\"/var/log/vmware/sso/lookupsvc-init.log\"
          Tag=\"ssolookupsvc-init\"
          PersistStateInterval=\"200\"
          Severity=\"info\"

startmsg.regex=\"^[[:digit:]]{4}-[[:digit:]]{1,2}-[[:digit:]]{1,2}T[[:digit:]]{1,2}:[[:digit:]]{1,2}:[[:digit:]]{1,2}.[[:digit:]]{0,3}Z\"
          Facility=\"local0\")
    input(type=\"imfile\"
          File=\"/var/log/vmware/sso/openidconnect.log\"
          Tag=\"openidconnect\"
          PersistStateInterval=\"200\"
          Severity=\"info\"

startmsg.regex=\"^[[:digit:]]{4}-[[:digit:]]{1,2}-[[:digit:]]{1,2}T[[:digit:]]{1,2}:[[:digit:]]{1,2}:[[:digit:]]{1,2}.[[:digit:]]{0,3}Z\"
          Facility=\"local0\")
    input(type=\"imfile\"
          File=\"/var/log/vmware/sso/ssoAdminServer.log\"
          Tag=\"ssoadminserver\"
          PersistStateInterval=\"200\"
          Severity=\"info\"

startmsg.regex=\"^[[:digit:]]{4}-[[:digit:]]{1,2}-[[:digit:]]{1,2}T[[:digit:]]{1,2}:[[:digit:]]{1,2}:[[:digit:]]{1,2}.[[:digit:]]{0,3}Z\"
          Facility=\"local0\")
    input(type=\"imfile\"
          File=\"/var/log/vmware/sso/svcaccountmgmt.log\"
          Tag=\"svcaccountmgmt\"
          PersistStateInterval=\"200\"
          Severity=\"info\"

startmsg.regex=\"^[[:digit:]]{4}-[[:digit:]]{1,2}-[[:digit:]]{1,2}T[[:digit:]]{1,2}:[[:digit:]]{1,2}:[[:digit:]]{1,2}.[[:digit:]]{0,3}Z\"
          Facility=\"local0\")
    input(type=\"imfile\"
          File=\"/var/log/vmware/sso/tokenservice.log\"
          Tag=\"tokenservice\"
          PersistStateInterval=\"200\"
          Severity=\"info\"

startmsg.regex=\"^[[:digit:]]{4}-[[:digit:]]{1,2}-[[:digit:]]{1,2}T[[:digit:]]{1,2}:[[:digit:]]{1,2}:[[:digit:]]{1,2}.[[:digit:]]{0,3}Z\"
          Facility=\"local0\")
    #sts health log
    input(type=\"imfile\"
          File=\"/var/log/vmware/sso/sts-health-status.log.*\"
          Tag=\"sts-health-status\"
          PersistStateInterval=\"200\"
          Severity=\"info\"
          startmsg.regex=\"^[[:digit:]]{4}-[[:digit:]]{1,2}-[[:digit:]]{1,2}
[[:digit:]]{1,2}:[[:digit:]]{1,2}:[[:digit:]]{1,2},[[:digit:]]{0,4}\"
          Facility=\"local0\")
    #sts runtime log
    input(type=\"imfile\"
          File=\"/var/log/vmware/sso/sts-runtime.log.*\"
          Tag=\"sts-runtime\"
          PersistStateInterval=\"200\"
          Severity=\"info\"
          Facility=\"local0\")
    #gclogFile.0.current log
    input(type=\"imfile\"
          File=\"/var/log/vmware/sso/gclogFile.*.current\"
          Tag=\"gclog\"
          PersistStateInterval=\"200\"
          Severity=\"info\"

startmsg.regex=\"^[[:digit:]]{4}-[[:digit:]]{1,2}-[[:digit:]]{1,2}T[[:digit:]]{1,2}:[[:digit:]]{1,2}:[[:digit:]]{1,2}.[[:digit:]]{0,3}+[[:digit:]]{0,4}\"
          Facility=\"local0\")
    #tomcat log
    input(type=\"imfile\"
          File=\"/var/log/vmware/sso/tomcat/localhost_access.log\"
          Tag=\"sso-tomcat\"
          PersistStateInterval=\"200\"
          Severity=\"info\"
          Facility=\"local0\")
    #vmdir log
    input(type=\"imfile\"
          File=\"/var/log/vmware/vmdir/*.log\"
          Tag=\"vmdir\"
          PersistStateInterval=\"200\"
          Severity=\"info\"
          Facility=\"local0\")
    #vmafd log
    input(type=\"imfile\"
          File=\"/var/log/vmware/vmafd/*.log\"
          Tag=\"vmafd\"
          PersistStateInterval=\"200\"
          Severity=\"info\"
          Facility=\"local0\")
  "
  impact 0.5
  tag severity: 'medium'
  tag gtitle: 'SRG-APP-000358-WSR-000163'
  tag gid: nil
  tag rid: nil
  tag stig_id: 'VCST-70-000027'
  tag fix_id: nil
  tag cci: 'CCI-001851'
  tag nist: ['AU-4 (1)']

  describe command('rpm -V VMware-visl-integration|grep vmware-services-sso-services.conf|grep "^..5......"') do
    its ('stdout.strip') { should eq '' }
  end

end

