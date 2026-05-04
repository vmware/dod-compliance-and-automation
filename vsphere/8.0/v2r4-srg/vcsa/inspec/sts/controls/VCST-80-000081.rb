control 'VCST-80-000081' do
  title 'The vCenter STS service must offload log records onto a different system or media from the system being logged.'
  desc  "
    Information system logging capability is critical for accurate forensic analysis. Log record content that may be necessary to satisfy the requirement of this control includes, but is not limited to, time stamps, source and destination IP addresses, user/process identifiers, event descriptions, application-specific events, success/fail indications, filenames involved, and access control or flow control rules invoked.

    Offloading is a common process in information systems with limited log storage capacity.

    Centralized management of log records provides for efficiency in maintenance and management of records, as well as the backup and archiving of those records. Application servers and their related components are required to offload log records onto a different system or media than the system being logged.
  "
  desc  'rationale', ''
  desc  'check', "
    By default, a vmware-services-sso-services.conf rsyslog configuration file includes the service logs when syslog is configured on vCenter, but it must be verified.

    At the command prompt, run the following command:

    # cat /etc/vmware-syslog/vmware-services-sso-services.conf

    Expected result:

    #vmidentity logs
    input(type=\"imfile\"
          File=\"/var/log/vmware/sso/activedirectoryservice.log\"
          Tag=\"activedirectoryservice\"
          PersistStateInterval=\"200\"
          Severity=\"info\"
          startmsg.regex=\"^[[:digit:]]{4}-[[:digit:]]{1,2}-[[:digit:]]{1,2}T[[:digit:]]{1,2}:[[:digit:]]{1,2}:[[:digit:]]{1,2}.[[:digit:]]{0,3}Z\"
          Facility=\"local0\"
          deleteStateOnFileDelete=\"on\"
          reopenOnTruncate=\"on\")
    input(type=\"imfile\"
          File=\"/var/log/vmware/sso/lookupsvc-init.log\"
          Tag=\"ssolookupsvc-init\"
          PersistStateInterval=\"200\"
          Severity=\"info\"
          startmsg.regex=\"^[[:digit:]]{4}-[[:digit:]]{1,2}-[[:digit:]]{1,2}T[[:digit:]]{1,2}:[[:digit:]]{1,2}:[[:digit:]]{1,2}.[[:digit:]]{0,3}Z\"
          Facility=\"local0\"
          deleteStateOnFileDelete=\"on\"
          reopenOnTruncate=\"on\")
    input(type=\"imfile\"
          File=\"/var/log/vmware/sso/openidconnect.log\"
          Tag=\"openidconnect\"
          PersistStateInterval=\"200\"
          Severity=\"info\"
          startmsg.regex=\"^[[:digit:]]{4}-[[:digit:]]{1,2}-[[:digit:]]{1,2}T[[:digit:]]{1,2}:[[:digit:]]{1,2}:[[:digit:]]{1,2}.[[:digit:]]{0,3}Z\"
          Facility=\"local0\"
          deleteStateOnFileDelete=\"on\"
          reopenOnTruncate=\"on\")
    input(type=\"imfile\"
          File=\"/var/log/vmware/sso/ssoAdminServer.log\"
          Tag=\"ssoadminserver\"
          PersistStateInterval=\"200\"
          Severity=\"info\"
          startmsg.regex=\"^[[:digit:]]{4}-[[:digit:]]{1,2}-[[:digit:]]{1,2}T[[:digit:]]{1,2}:[[:digit:]]{1,2}:[[:digit:]]{1,2}.[[:digit:]]{0,3}Z\"
          Facility=\"local0\"
          deleteStateOnFileDelete=\"on\"
          reopenOnTruncate=\"on\")
    input(type=\"imfile\"
          File=\"/var/log/vmware/sso/svcaccountmgmt.log\"
          Tag=\"svcaccountmgmt\"
          PersistStateInterval=\"200\"
          Severity=\"info\"
          startmsg.regex=\"^[[:digit:]]{4}-[[:digit:]]{1,2}-[[:digit:]]{1,2}T[[:digit:]]{1,2}:[[:digit:]]{1,2}:[[:digit:]]{1,2}.[[:digit:]]{0,3}Z\"
          Facility=\"local0\"
          deleteStateOnFileDelete=\"on\"
          reopenOnTruncate=\"on\")
    input(type=\"imfile\"
          File=\"/var/log/vmware/sso/tokenservice.log\"
          Tag=\"tokenservice\"
          PersistStateInterval=\"200\"
          Severity=\"info\"
          startmsg.regex=\"^[[:digit:]]{4}-[[:digit:]]{1,2}-[[:digit:]]{1,2}T[[:digit:]]{1,2}:[[:digit:]]{1,2}:[[:digit:]]{1,2}.[[:digit:]]{0,3}Z\"
          Facility=\"local0\"
          deleteStateOnFileDelete=\"on\"
          reopenOnTruncate=\"on\")
    #sts health log
    input(type=\"imfile\"
          File=\"/var/log/vmware/sso/sts-health-status.log\"
          Tag=\"sts-health-status\"
          PersistStateInterval=\"200\"
          Severity=\"info\"
          startmsg.regex=\"^[[:digit:]]{4}-[[:digit:]]{1,2}-[[:digit:]]{1,2} [[:digit:]]{1,2}:[[:digit:]]{1,2}:[[:digit:]]{1,2},[[:digit:]]{0,4}\"
          Facility=\"local0\"
          deleteStateOnFileDelete=\"on\"
          reopenOnTruncate=\"on\")
    #sts runtime log stdout
    input(type=\"imfile\"
          File=\"/var/log/vmware/sso/sts-runtime.log.stdout\"
          Tag=\"sts-runtime-stdout\"
          PersistStateInterval=\"200\"
          Severity=\"info\"
          Facility=\"local0\"
          deleteStateOnFileDelete=\"on\"
          reopenOnTruncate=\"on\")
    #sts runtime log stderr
    input(type=\"imfile\"
          File=\"/var/log/vmware/sso/sts-runtime.log.stderr\"
          Tag=\"sts-runtime-stderr\"
          PersistStateInterval=\"200\"
          Severity=\"info\"
          Facility=\"local0\"
          deleteStateOnFileDelete=\"on\"
          reopenOnTruncate=\"on\")
    #gclogFile.0.current log
    input(type=\"imfile\"
          File=\"/var/log/vmware/sso/gclogFile.*.current\"
          Tag=\"gclog\"
          PersistStateInterval=\"200\"
          Severity=\"info\"
          startmsg.regex=\"^[[:digit:]]{4}-[[:digit:]]{1,2}-[[:digit:]]{1,2}T[[:digit:]]{1,2}:[[:digit:]]{1,2}:[[:digit:]]{1,2}.[[:digit:]]{0,3}+[[:digit:]]{0,4}\"
          Facility=\"local0\"
          deleteStateOnFileDelete=\"on\"
          reopenOnTruncate=\"on\")
    #identity sts default
    input(type=\"imfile\"
          File=\"/var/log/vmware/sso/vmware-identity-sts-default.log\"
          Tag=\"sso-identity-sts-default\"
          PersistStateInterval=\"200\"
          Severity=\"info\"
          Facility=\"local0\"
          deleteStateOnFileDelete=\"on\"
          reopenOnTruncate=\"on\")
    #identity sts
    input(type=\"imfile\"
          File=\"/var/log/vmware/sso/vmware-identity-sts.log\"
          Tag=\"sso-identity-sts\"
          PersistStateInterval=\"200\"
          Severity=\"info\"
          Facility=\"local0\"
          deleteStateOnFileDelete=\"on\"
          reopenOnTruncate=\"on\")
    #identity perf
    input(type=\"imfile\"
          File=\"/var/log/vmware/sso/vmware-identity-sts-perf.log\"
          Tag=\"sso-identity-perf\"
          PersistStateInterval=\"200\"
          Severity=\"info\"
          Facility=\"local0\"
          deleteStateOnFileDelete=\"on\"
          reopenOnTruncate=\"on\")
    #identity prestart
    input(type=\"imfile\"
          File=\"/var/log/vmware/sso/sts-prestart.log\"
          Tag=\"sso-identity-prestart\"
          PersistStateInterval=\"200\"
          Severity=\"info\"
          Facility=\"local0\"
          deleteStateOnFileDelete=\"on\"
          reopenOnTruncate=\"on\")
    #rest idm
    input(type=\"imfile\"
          File=\"/var/log/vmware/sso/vmware-rest-idm.log\"
          Tag=\"sso-rest-idm\"
          PersistStateInterval=\"200\"
          Severity=\"info\"
          Facility=\"local0\"
          deleteStateOnFileDelete=\"on\"
          reopenOnTruncate=\"on\")
    #rest vmdir
    input(type=\"imfile\"
          File=\"/var/log/vmware/sso/vmware-rest-vmdir.log\"
          Tag=\"sso-rest-vmdir\"
          PersistStateInterval=\"200\"
          Severity=\"info\"
          Facility=\"local0\"
          deleteStateOnFileDelete=\"on\"
          reopenOnTruncate=\"on\")
    #rest afd
    input(type=\"imfile\"
          File=\"/var/log/vmware/sso/vmware-rest-afd.log\"
          Tag=\"sso-rest-afd\"
          PersistStateInterval=\"200\"
          Severity=\"info\"
          Facility=\"local0\"
          deleteStateOnFileDelete=\"on\"
          reopenOnTruncate=\"on\")
    #websso
    input(type=\"imfile\"
          File=\"/var/log/vmware/sso/websso.log\"
          Tag=\"sso-websso\"
          PersistStateInterval=\"200\"
          Severity=\"info\"
          Facility=\"local0\"
          deleteStateOnFileDelete=\"on\"
          reopenOnTruncate=\"on\")
    #tomcat catalina
    input(type=\"imfile\"
          File=\"/var/log/vmware/sso/tomcat/catalina.*.log\"
          Tag=\"sso-tomcat-catalina\"
          PersistStateInterval=\"200\"
          Severity=\"info\"
          Facility=\"local0\"
          deleteStateOnFileDelete=\"on\"
          reopenOnTruncate=\"on\")
    #tomcat localhost
    input(type=\"imfile\"
          File=\"/var/log/vmware/sso/tomcat/localhost.*.log\"
          Tag=\"sso-tomcat-localhost\"
          PersistStateInterval=\"200\"
          Severity=\"info\"
          Facility=\"local0\"
          deleteStateOnFileDelete=\"on\"
          reopenOnTruncate=\"on\")
    #tomcat localhost access
    input(type=\"imfile\"
          File=\"/var/log/vmware/sso/tomcat/localhost_access.log\"
          Tag=\"sso-tomcat-localhost-access\"
          PersistStateInterval=\"200\"
          Severity=\"info\"
          Facility=\"local0\"
          deleteStateOnFileDelete=\"on\"
          reopenOnTruncate=\"on\")
    #vmdir log
    input(type=\"imfile\"
          File=\"/var/log/vmware/vmdir/*.log\"
          Tag=\"vmdir\"
          PersistStateInterval=\"200\"
          Severity=\"info\"
          Facility=\"local0\"
          deleteStateOnFileDelete=\"on\"
          reopenOnTruncate=\"on\")
    #vmafd log
    input(type=\"imfile\"
          File=\"/var/log/vmware/vmafd/*.log\"
          Tag=\"vmafd\"
          PersistStateInterval=\"200\"
          Severity=\"info\"
          Facility=\"local0\"
          deleteStateOnFileDelete=\"on\"
          reopenOnTruncate=\"on\")

    Note: If the entries for \"deleteStateOnFileDelete\" and \"reopenOnTruncate\" do not exist, this is not a finding.

    If the output does not match the expected result, this is a finding.
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
          Facility=\"local0\"
          deleteStateOnFileDelete=\"on\"
          reopenOnTruncate=\"on\")
    input(type=\"imfile\"
          File=\"/var/log/vmware/sso/lookupsvc-init.log\"
          Tag=\"ssolookupsvc-init\"
          PersistStateInterval=\"200\"
          Severity=\"info\"
          startmsg.regex=\"^[[:digit:]]{4}-[[:digit:]]{1,2}-[[:digit:]]{1,2}T[[:digit:]]{1,2}:[[:digit:]]{1,2}:[[:digit:]]{1,2}.[[:digit:]]{0,3}Z\"
          Facility=\"local0\"
          deleteStateOnFileDelete=\"on\"
          reopenOnTruncate=\"on\")
    input(type=\"imfile\"
          File=\"/var/log/vmware/sso/openidconnect.log\"
          Tag=\"openidconnect\"
          PersistStateInterval=\"200\"
          Severity=\"info\"
          startmsg.regex=\"^[[:digit:]]{4}-[[:digit:]]{1,2}-[[:digit:]]{1,2}T[[:digit:]]{1,2}:[[:digit:]]{1,2}:[[:digit:]]{1,2}.[[:digit:]]{0,3}Z\"
          Facility=\"local0\"
          deleteStateOnFileDelete=\"on\"
          reopenOnTruncate=\"on\")
    input(type=\"imfile\"
          File=\"/var/log/vmware/sso/ssoAdminServer.log\"
          Tag=\"ssoadminserver\"
          PersistStateInterval=\"200\"
          Severity=\"info\"
          startmsg.regex=\"^[[:digit:]]{4}-[[:digit:]]{1,2}-[[:digit:]]{1,2}T[[:digit:]]{1,2}:[[:digit:]]{1,2}:[[:digit:]]{1,2}.[[:digit:]]{0,3}Z\"
          Facility=\"local0\"
          deleteStateOnFileDelete=\"on\"
          reopenOnTruncate=\"on\")
    input(type=\"imfile\"
          File=\"/var/log/vmware/sso/svcaccountmgmt.log\"
          Tag=\"svcaccountmgmt\"
          PersistStateInterval=\"200\"
          Severity=\"info\"
          startmsg.regex=\"^[[:digit:]]{4}-[[:digit:]]{1,2}-[[:digit:]]{1,2}T[[:digit:]]{1,2}:[[:digit:]]{1,2}:[[:digit:]]{1,2}.[[:digit:]]{0,3}Z\"
          Facility=\"local0\"
          deleteStateOnFileDelete=\"on\"
          reopenOnTruncate=\"on\")
    input(type=\"imfile\"
          File=\"/var/log/vmware/sso/tokenservice.log\"
          Tag=\"tokenservice\"
          PersistStateInterval=\"200\"
          Severity=\"info\"
          startmsg.regex=\"^[[:digit:]]{4}-[[:digit:]]{1,2}-[[:digit:]]{1,2}T[[:digit:]]{1,2}:[[:digit:]]{1,2}:[[:digit:]]{1,2}.[[:digit:]]{0,3}Z\"
          Facility=\"local0\"
          deleteStateOnFileDelete=\"on\"
          reopenOnTruncate=\"on\")
    #sts health log
    input(type=\"imfile\"
          File=\"/var/log/vmware/sso/sts-health-status.log\"
          Tag=\"sts-health-status\"
          PersistStateInterval=\"200\"
          Severity=\"info\"
          startmsg.regex=\"^[[:digit:]]{4}-[[:digit:]]{1,2}-[[:digit:]]{1,2} [[:digit:]]{1,2}:[[:digit:]]{1,2}:[[:digit:]]{1,2},[[:digit:]]{0,4}\"
          Facility=\"local0\"
          deleteStateOnFileDelete=\"on\"
          reopenOnTruncate=\"on\")
    #sts runtime log stdout
    input(type=\"imfile\"
          File=\"/var/log/vmware/sso/sts-runtime.log.stdout\"
          Tag=\"sts-runtime-stdout\"
          PersistStateInterval=\"200\"
          Severity=\"info\"
          Facility=\"local0\"
          deleteStateOnFileDelete=\"on\"
          reopenOnTruncate=\"on\")
    #sts runtime log stderr
    input(type=\"imfile\"
          File=\"/var/log/vmware/sso/sts-runtime.log.stderr\"
          Tag=\"sts-runtime-stderr\"
          PersistStateInterval=\"200\"
          Severity=\"info\"
          Facility=\"local0\"
          deleteStateOnFileDelete=\"on\"
          reopenOnTruncate=\"on\")
    #gclogFile.0.current log
    input(type=\"imfile\"
          File=\"/var/log/vmware/sso/gclogFile.*.current\"
          Tag=\"gclog\"
          PersistStateInterval=\"200\"
          Severity=\"info\"
          startmsg.regex=\"^[[:digit:]]{4}-[[:digit:]]{1,2}-[[:digit:]]{1,2}T[[:digit:]]{1,2}:[[:digit:]]{1,2}:[[:digit:]]{1,2}.[[:digit:]]{0,3}+[[:digit:]]{0,4}\"
          Facility=\"local0\"
          deleteStateOnFileDelete=\"on\"
          reopenOnTruncate=\"on\")
    #identity sts default
    input(type=\"imfile\"
          File=\"/var/log/vmware/sso/vmware-identity-sts-default.log\"
          Tag=\"sso-identity-sts-default\"
          PersistStateInterval=\"200\"
          Severity=\"info\"
          Facility=\"local0\"
          deleteStateOnFileDelete=\"on\"
          reopenOnTruncate=\"on\")
    #identity sts
    input(type=\"imfile\"
          File=\"/var/log/vmware/sso/vmware-identity-sts.log\"
          Tag=\"sso-identity-sts\"
          PersistStateInterval=\"200\"
          Severity=\"info\"
          Facility=\"local0\"
          deleteStateOnFileDelete=\"on\"
          reopenOnTruncate=\"on\")
    #identity perf
    input(type=\"imfile\"
          File=\"/var/log/vmware/sso/vmware-identity-sts-perf.log\"
          Tag=\"sso-identity-perf\"
          PersistStateInterval=\"200\"
          Severity=\"info\"
          Facility=\"local0\"
          deleteStateOnFileDelete=\"on\"
          reopenOnTruncate=\"on\")
    #identity prestart
    input(type=\"imfile\"
          File=\"/var/log/vmware/sso/sts-prestart.log\"
          Tag=\"sso-identity-prestart\"
          PersistStateInterval=\"200\"
          Severity=\"info\"
          Facility=\"local0\"
          deleteStateOnFileDelete=\"on\"
          reopenOnTruncate=\"on\")
    #rest idm
    input(type=\"imfile\"
          File=\"/var/log/vmware/sso/vmware-rest-idm.log\"
          Tag=\"sso-rest-idm\"
          PersistStateInterval=\"200\"
          Severity=\"info\"
          Facility=\"local0\"
          deleteStateOnFileDelete=\"on\"
          reopenOnTruncate=\"on\")
    #rest vmdir
    input(type=\"imfile\"
          File=\"/var/log/vmware/sso/vmware-rest-vmdir.log\"
          Tag=\"sso-rest-vmdir\"
          PersistStateInterval=\"200\"
          Severity=\"info\"
          Facility=\"local0\"
          deleteStateOnFileDelete=\"on\"
          reopenOnTruncate=\"on\")
    #rest afd
    input(type=\"imfile\"
          File=\"/var/log/vmware/sso/vmware-rest-afd.log\"
          Tag=\"sso-rest-afd\"
          PersistStateInterval=\"200\"
          Severity=\"info\"
          Facility=\"local0\"
          deleteStateOnFileDelete=\"on\"
          reopenOnTruncate=\"on\")
    #websso
    input(type=\"imfile\"
          File=\"/var/log/vmware/sso/websso.log\"
          Tag=\"sso-websso\"
          PersistStateInterval=\"200\"
          Severity=\"info\"
          Facility=\"local0\"
          deleteStateOnFileDelete=\"on\"
          reopenOnTruncate=\"on\")
    #tomcat catalina
    input(type=\"imfile\"
          File=\"/var/log/vmware/sso/tomcat/catalina.*.log\"
          Tag=\"sso-tomcat-catalina\"
          PersistStateInterval=\"200\"
          Severity=\"info\"
          Facility=\"local0\"
          deleteStateOnFileDelete=\"on\"
          reopenOnTruncate=\"on\")
    #tomcat localhost
    input(type=\"imfile\"
          File=\"/var/log/vmware/sso/tomcat/localhost.*.log\"
          Tag=\"sso-tomcat-localhost\"
          PersistStateInterval=\"200\"
          Severity=\"info\"
          Facility=\"local0\"
          deleteStateOnFileDelete=\"on\"
          reopenOnTruncate=\"on\")
    #tomcat localhost access
    input(type=\"imfile\"
          File=\"/var/log/vmware/sso/tomcat/localhost_access.log\"
          Tag=\"sso-tomcat-localhost-access\"
          PersistStateInterval=\"200\"
          Severity=\"info\"
          Facility=\"local0\"
          deleteStateOnFileDelete=\"on\"
          reopenOnTruncate=\"on\")
    #vmdir log
    input(type=\"imfile\"
          File=\"/var/log/vmware/vmdir/*.log\"
          Tag=\"vmdir\"
          PersistStateInterval=\"200\"
          Severity=\"info\"
          Facility=\"local0\"
          deleteStateOnFileDelete=\"on\"
          reopenOnTruncate=\"on\")
    #vmafd log
    input(type=\"imfile\"
          File=\"/var/log/vmware/vmafd/*.log\"
          Tag=\"vmafd\"
          PersistStateInterval=\"200\"
          Severity=\"info\"
          Facility=\"local0\"
          deleteStateOnFileDelete=\"on\"
          reopenOnTruncate=\"on\")
  "
  impact 0.5
  tag severity: 'medium'
  tag gtitle: 'SRG-APP-000358-AS-000064'
  tag gid: 'V-VCST-80-000081'
  tag rid: 'SV-VCST-80-000081'
  tag stig_id: 'VCST-80-000081'
  tag cci: ['CCI-001851']
  tag nist: ['AU-4 (1)']

  goodcontent_v1 = inspec.profile.file('vmware-services-sso-services-v1.conf')
  goodcontent_v2 = inspec.profile.file('vmware-services-sso-services-v2.conf')

  describe.one do
    describe file('/etc/vmware-syslog/vmware-services-sso-services.conf') do
      its('content') { should eq goodcontent_v1 }
    end
    describe file('/etc/vmware-syslog/vmware-services-sso-services.conf') do
      its('content') { should eq goodcontent_v2 }
    end
  end
end
