control 'VCST-80-000081' do
  title 'The vCenter STS service must offload log records onto a different system or media from the system being logged.'
  desc 'Information system logging capability is critical for accurate forensic analysis. Log record content that may be necessary to satisfy the requirement of this control includes, but is not limited to, time stamps, source and destination IP addresses, user/process identifiers, event descriptions, application-specific events, success/fail indications, filenames involved, and access control or flow control rules invoked.

Offloading is a common process in information systems with limited log storage capacity.

Centralized management of log records provides for efficiency in maintenance and management of records, as well as the backup and archiving of those records. Application servers and their related components are required to offload log records onto a different system or media than the system being logged.'
  desc 'check', 'By default, a vmware-services-sso-services.conf rsyslog configuration file includes the service logs when syslog is configured on vCenter, but it must be verified.

At the command prompt, run the following command:

# cat /etc/vmware-syslog/vmware-services-sso-services.conf

Expected result:

#vmidentity logs
input(type="imfile"
      File="/var/log/vmware/sso/activedirectoryservice.log"
      Tag="activedirectoryservice"
      PersistStateInterval="200"
      Severity="info"
      startmsg.regex="^[[:digit:]]{4}-[[:digit:]]{1,2}-[[:digit:]]{1,2}T[[:digit:]]{1,2}:[[:digit:]]{1,2}:[[:digit:]]{1,2}.[[:digit:]]{0,3}Z"
      Facility="local0")
input(type="imfile"
      File="/var/log/vmware/sso/lookupsvc-init.log"
      Tag="ssolookupsvc-init"
      PersistStateInterval="200"
      Severity="info"
      startmsg.regex="^[[:digit:]]{4}-[[:digit:]]{1,2}-[[:digit:]]{1,2}T[[:digit:]]{1,2}:[[:digit:]]{1,2}:[[:digit:]]{1,2}.[[:digit:]]{0,3}Z"
      Facility="local0")
input(type="imfile"
      File="/var/log/vmware/sso/openidconnect.log"
      Tag="openidconnect"
      PersistStateInterval="200"
      Severity="info"
      startmsg.regex="^[[:digit:]]{4}-[[:digit:]]{1,2}-[[:digit:]]{1,2}T[[:digit:]]{1,2}:[[:digit:]]{1,2}:[[:digit:]]{1,2}.[[:digit:]]{0,3}Z"
      Facility="local0")
input(type="imfile"
      File="/var/log/vmware/sso/ssoAdminServer.log"
      Tag="ssoadminserver"
      PersistStateInterval="200"
      Severity="info"
      startmsg.regex="^[[:digit:]]{4}-[[:digit:]]{1,2}-[[:digit:]]{1,2}T[[:digit:]]{1,2}:[[:digit:]]{1,2}:[[:digit:]]{1,2}.[[:digit:]]{0,3}Z"
      Facility="local0")
input(type="imfile"
      File="/var/log/vmware/sso/svcaccountmgmt.log"
      Tag="svcaccountmgmt"
      PersistStateInterval="200"
      Severity="info"
      startmsg.regex="^[[:digit:]]{4}-[[:digit:]]{1,2}-[[:digit:]]{1,2}T[[:digit:]]{1,2}:[[:digit:]]{1,2}:[[:digit:]]{1,2}.[[:digit:]]{0,3}Z"
      Facility="local0")
input(type="imfile"
      File="/var/log/vmware/sso/tokenservice.log"
      Tag="tokenservice"
      PersistStateInterval="200"
      Severity="info"
      startmsg.regex="^[[:digit:]]{4}-[[:digit:]]{1,2}-[[:digit:]]{1,2}T[[:digit:]]{1,2}:[[:digit:]]{1,2}:[[:digit:]]{1,2}.[[:digit:]]{0,3}Z"
      Facility="local0")
#sts health log
input(type="imfile"
      File="/var/log/vmware/sso/sts-health-status.log"
      Tag="sts-health-status"
      PersistStateInterval="200"
      Severity="info"
      startmsg.regex="^[[:digit:]]{4}-[[:digit:]]{1,2}-[[:digit:]]{1,2} [[:digit:]]{1,2}:[[:digit:]]{1,2}:[[:digit:]]{1,2},[[:digit:]]{0,4}"
      Facility="local0")
#sts runtime log stdout
input(type="imfile"
      File="/var/log/vmware/sso/sts-runtime.log.stdout"
      Tag="sts-runtime-stdout"
      PersistStateInterval="200"
      Severity="info"
      Facility="local0")
#sts runtime log stderr
input(type="imfile"
      File="/var/log/vmware/sso/sts-runtime.log.stderr"
      Tag="sts-runtime-stderr"
      PersistStateInterval="200"
      Severity="info"
      Facility="local0")
#gclogFile.0.current log
input(type="imfile"
      File="/var/log/vmware/sso/gclogFile.*.current"
      Tag="gclog"
      PersistStateInterval="200"
      Severity="info"
      startmsg.regex="^[[:digit:]]{4}-[[:digit:]]{1,2}-[[:digit:]]{1,2}T[[:digit:]]{1,2}:[[:digit:]]{1,2}:[[:digit:]]{1,2}.[[:digit:]]{0,3}+[[:digit:]]{0,4}"
      Facility="local0")
#identity sts default
input(type="imfile"
      File="/var/log/vmware/sso/vmware-identity-sts-default.log"
      Tag="sso-identity-sts-default"
      PersistStateInterval="200"
      Severity="info"
      Facility="local0")
#identity sts
input(type="imfile"
      File="/var/log/vmware/sso/vmware-identity-sts.log"
      Tag="sso-identity-sts"
      PersistStateInterval="200"
      Severity="info"
      Facility="local0")
#identity perf
input(type="imfile"
      File="/var/log/vmware/sso/vmware-identity-sts-perf.log"
      Tag="sso-identity-perf"
      PersistStateInterval="200"
      Severity="info"
      Facility="local0")
#identity prestart
input(type="imfile"
      File="/var/log/vmware/sso/sts-prestart.log"
      Tag="sso-identity-prestart"
      PersistStateInterval="200"
      Severity="info"
      Facility="local0")
#rest idm
input(type="imfile"
      File="/var/log/vmware/sso/vmware-rest-idm.log"
      Tag="sso-rest-idm"
      PersistStateInterval="200"
      Severity="info"
      Facility="local0")
#rest vmdir
input(type="imfile"
      File="/var/log/vmware/sso/vmware-rest-vmdir.log"
      Tag="sso-rest-vmdir"
      PersistStateInterval="200"
      Severity="info"
      Facility="local0")
#rest afd
input(type="imfile"
      File="/var/log/vmware/sso/vmware-rest-afd.log"
      Tag="sso-rest-afd"
      PersistStateInterval="200"
      Severity="info"
      Facility="local0")
#websso
input(type="imfile"
      File="/var/log/vmware/sso/websso.log"
      Tag="sso-websso"
      PersistStateInterval="200"
      Severity="info"
      Facility="local0")
#tomcat catalina
input(type="imfile"
      File="/var/log/vmware/sso/tomcat/catalina.*.log"
      Tag="sso-tomcat-catalina"
      PersistStateInterval="200"
      Severity="info"
      Facility="local0")
#tomcat localhost
input(type="imfile"
      File="/var/log/vmware/sso/tomcat/localhost.*.log"
      Tag="sso-tomcat-localhost"
      PersistStateInterval="200"
      Severity="info"
      Facility="local0")
#tomcat localhost access
input(type="imfile"
      File="/var/log/vmware/sso/tomcat/localhost_access.log"
      Tag="sso-tomcat-localhost-access"
      PersistStateInterval="200"
      Severity="info"
      Facility="local0")
#vmdir log
input(type="imfile"
      File="/var/log/vmware/vmdir/*.log"
      Tag="vmdir"
      PersistStateInterval="200"
      Severity="info"
      Facility="local0")
#vmafd log
input(type="imfile"
      File="/var/log/vmware/vmafd/*.log"
      Tag="vmafd"
      PersistStateInterval="200"
      Severity="info"
      Facility="local0")

If the output does not match the expected result, this is a finding.'
  desc 'fix', 'Navigate to and open:

/etc/vmware-syslog/vmware-services-sso-services.conf

Create the file if it does not exist.

Set the contents of the file as follows:

#vmidentity logs
input(type="imfile"
      File="/var/log/vmware/sso/activedirectoryservice.log"
      Tag="activedirectoryservice"
      PersistStateInterval="200"
      Severity="info"
      startmsg.regex="^[[:digit:]]{4}-[[:digit:]]{1,2}-[[:digit:]]{1,2}T[[:digit:]]{1,2}:[[:digit:]]{1,2}:[[:digit:]]{1,2}.[[:digit:]]{0,3}Z"
      Facility="local0")
input(type="imfile"
      File="/var/log/vmware/sso/lookupsvc-init.log"
      Tag="ssolookupsvc-init"
      PersistStateInterval="200"
      Severity="info"
      startmsg.regex="^[[:digit:]]{4}-[[:digit:]]{1,2}-[[:digit:]]{1,2}T[[:digit:]]{1,2}:[[:digit:]]{1,2}:[[:digit:]]{1,2}.[[:digit:]]{0,3}Z"
      Facility="local0")
input(type="imfile"
      File="/var/log/vmware/sso/openidconnect.log"
      Tag="openidconnect"
      PersistStateInterval="200"
      Severity="info"
      startmsg.regex="^[[:digit:]]{4}-[[:digit:]]{1,2}-[[:digit:]]{1,2}T[[:digit:]]{1,2}:[[:digit:]]{1,2}:[[:digit:]]{1,2}.[[:digit:]]{0,3}Z"
      Facility="local0")
input(type="imfile"
      File="/var/log/vmware/sso/ssoAdminServer.log"
      Tag="ssoadminserver"
      PersistStateInterval="200"
      Severity="info"
      startmsg.regex="^[[:digit:]]{4}-[[:digit:]]{1,2}-[[:digit:]]{1,2}T[[:digit:]]{1,2}:[[:digit:]]{1,2}:[[:digit:]]{1,2}.[[:digit:]]{0,3}Z"
      Facility="local0")
input(type="imfile"
      File="/var/log/vmware/sso/svcaccountmgmt.log"
      Tag="svcaccountmgmt"
      PersistStateInterval="200"
      Severity="info"
      startmsg.regex="^[[:digit:]]{4}-[[:digit:]]{1,2}-[[:digit:]]{1,2}T[[:digit:]]{1,2}:[[:digit:]]{1,2}:[[:digit:]]{1,2}.[[:digit:]]{0,3}Z"
      Facility="local0")
input(type="imfile"
      File="/var/log/vmware/sso/tokenservice.log"
      Tag="tokenservice"
      PersistStateInterval="200"
      Severity="info"
      startmsg.regex="^[[:digit:]]{4}-[[:digit:]]{1,2}-[[:digit:]]{1,2}T[[:digit:]]{1,2}:[[:digit:]]{1,2}:[[:digit:]]{1,2}.[[:digit:]]{0,3}Z"
      Facility="local0")
#sts health log
input(type="imfile"
      File="/var/log/vmware/sso/sts-health-status.log"
      Tag="sts-health-status"
      PersistStateInterval="200"
      Severity="info"
      startmsg.regex="^[[:digit:]]{4}-[[:digit:]]{1,2}-[[:digit:]]{1,2} [[:digit:]]{1,2}:[[:digit:]]{1,2}:[[:digit:]]{1,2},[[:digit:]]{0,4}"
      Facility="local0")
#sts runtime log stdout
input(type="imfile"
      File="/var/log/vmware/sso/sts-runtime.log.stdout"
      Tag="sts-runtime-stdout"
      PersistStateInterval="200"
      Severity="info"
      Facility="local0")
#sts runtime log stderr
input(type="imfile"
      File="/var/log/vmware/sso/sts-runtime.log.stderr"
      Tag="sts-runtime-stderr"
      PersistStateInterval="200"
      Severity="info"
      Facility="local0")
#gclogFile.0.current log
input(type="imfile"
      File="/var/log/vmware/sso/gclogFile.*.current"
      Tag="gclog"
      PersistStateInterval="200"
      Severity="info"
      startmsg.regex="^[[:digit:]]{4}-[[:digit:]]{1,2}-[[:digit:]]{1,2}T[[:digit:]]{1,2}:[[:digit:]]{1,2}:[[:digit:]]{1,2}.[[:digit:]]{0,3}+[[:digit:]]{0,4}"
      Facility="local0")
#identity sts default
input(type="imfile"
      File="/var/log/vmware/sso/vmware-identity-sts-default.log"
      Tag="sso-identity-sts-default"
      PersistStateInterval="200"
      Severity="info"
      Facility="local0")
#identity sts
input(type="imfile"
      File="/var/log/vmware/sso/vmware-identity-sts.log"
      Tag="sso-identity-sts"
      PersistStateInterval="200"
      Severity="info"
      Facility="local0")
#identity perf
input(type="imfile"
      File="/var/log/vmware/sso/vmware-identity-sts-perf.log"
      Tag="sso-identity-perf"
      PersistStateInterval="200"
      Severity="info"
      Facility="local0")
#identity prestart
input(type="imfile"
      File="/var/log/vmware/sso/sts-prestart.log"
      Tag="sso-identity-prestart"
      PersistStateInterval="200"
      Severity="info"
      Facility="local0")
#rest idm
input(type="imfile"
      File="/var/log/vmware/sso/vmware-rest-idm.log"
      Tag="sso-rest-idm"
      PersistStateInterval="200"
      Severity="info"
      Facility="local0")
#rest vmdir
input(type="imfile"
      File="/var/log/vmware/sso/vmware-rest-vmdir.log"
      Tag="sso-rest-vmdir"
      PersistStateInterval="200"
      Severity="info"
      Facility="local0")
#rest afd
input(type="imfile"
      File="/var/log/vmware/sso/vmware-rest-afd.log"
      Tag="sso-rest-afd"
      PersistStateInterval="200"
      Severity="info"
      Facility="local0")
#websso
input(type="imfile"
      File="/var/log/vmware/sso/websso.log"
      Tag="sso-websso"
      PersistStateInterval="200"
      Severity="info"
      Facility="local0")
#tomcat catalina
input(type="imfile"
      File="/var/log/vmware/sso/tomcat/catalina.*.log"
      Tag="sso-tomcat-catalina"
      PersistStateInterval="200"
      Severity="info"
      Facility="local0")
#tomcat localhost
input(type="imfile"
      File="/var/log/vmware/sso/tomcat/localhost.*.log"
      Tag="sso-tomcat-localhost"
      PersistStateInterval="200"
      Severity="info"
      Facility="local0")
#tomcat localhost access
input(type="imfile"
      File="/var/log/vmware/sso/tomcat/localhost_access.log"
      Tag="sso-tomcat-localhost-access"
      PersistStateInterval="200"
      Severity="info"
      Facility="local0")
#vmdir log
input(type="imfile"
      File="/var/log/vmware/vmdir/*.log"
      Tag="vmdir"
      PersistStateInterval="200"
      Severity="info"
      Facility="local0")
#vmafd log
input(type="imfile"
      File="/var/log/vmware/vmafd/*.log"
      Tag="vmafd"
      PersistStateInterval="200"
      Severity="info"
      Facility="local0")'
  impact 0.5
  tag check_id: 'C-62724r934608_chk'
  tag severity: 'medium'
  tag gid: 'V-258984'
  tag rid: 'SV-258984r961395_rule'
  tag stig_id: 'VCST-80-000081'
  tag gtitle: 'SRG-APP-000358-AS-000064'
  tag fix_id: 'F-62633r934609_fix'
  tag cci: ['CCI-001851']
  tag nist: ['AU-4 (1)']

  goodcontent = inspec.profile.file('vmware-services-sso-services.conf')
  describe file('/etc/vmware-syslog/vmware-services-sso-services.conf') do
    its('content') { should eq goodcontent }
  end
end
