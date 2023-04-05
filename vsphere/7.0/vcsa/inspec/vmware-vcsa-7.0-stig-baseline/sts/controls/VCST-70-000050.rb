control 'VCST-70-000050' do
  title 'Security Token Service log data and records must be backed up onto a different system or media.'
  desc  'Protection of Security Token Service log data includes ensuring log data is not accidentally lost or deleted. Backing up Security Token Service log records to an unrelated system or onto separate media than the system the web server is running on helps to ensure that, in the event of a catastrophic system failure, the log records will be retained.'
  desc  'rationale', ''
  desc  'check', "
    At the command prompt, run the following command:

    # rpm -V VMware-visl-integration|grep vmware-services-sso-services.conf|grep \"^..5......\"

    If the command returns any output, this is a finding.
  "
  desc 'fix', "
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
          startmsg.regex=\"^[[:digit:]]{4}-[[:digit:]]{1,2}-[[:digit:]]{1,2} [[:digit:]]{1,2}:[[:digit:]]{1,2}:[[:digit:]]{1,2},[[:digit:]]{0,4}\"
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
  tag gtitle: 'SRG-APP-000125-WSR-000071'
  tag satisfies: ['SRG-APP-000358-WSR-000163']
  tag gid: 'V-256775'
  tag rid: 'SV-256775r889295_rule'
  tag stig_id: 'VCST-70-000050'
  tag cci: ['CCI-001348', 'CCI-001851']
  tag nist: ['AU-4 (1)', 'AU-9 (2)']

  describe command('rpm -V VMware-visl-integration|grep vmware-services-sso-services.conf|grep "^..5......"') do
    its('stdout.strip') { should eq '' }
  end
end
