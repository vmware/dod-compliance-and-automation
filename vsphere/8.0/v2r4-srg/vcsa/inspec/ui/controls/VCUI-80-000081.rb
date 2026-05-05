control 'VCUI-80-000081' do
  title 'The vCenter UI service must offload log records onto a different system or media from the system being logged.'
  desc  "
    Information system logging capability is critical for accurate forensic analysis. Log record content that may be necessary to satisfy the requirement of this control includes, but is not limited to, time stamps, source and destination IP addresses, user/process identifiers, event descriptions, application-specific events, success/fail indications, filenames involved, and access control or flow control rules invoked.

    Offloading is a common process in information systems with limited log storage capacity.

    Centralized management of log records provides for efficiency in maintenance and management of records, as well as the backup and archiving of those records. Application servers and their related components are required to offload log records onto a different system or media than the system being logged.
  "
  desc  'rationale', ''
  desc  'check', "
    By default, a vmware-services-vsphere-ui.conf rsyslog configuration file that includes the service logs when syslog is configured on vCenter, but it must be verified.

    At the command prompt, run the following command:

    # cat /etc/vmware-syslog/vmware-services-vsphere-ui.conf

    Expected result:

    #vsphere-ui main log
    input(type=\"imfile\"
          File=\"/var/log/vmware/vsphere-ui/logs/vsphere_client_virgo.log\"
          Tag=\"ui-main\"
          Severity=\"info\"
          Facility=\"local0\"
          deleteStateOnFileDelete=\"on\"
          reopenOnTruncate=\"on\")
    #vsphere-ui change log
    input(type=\"imfile\"
          File=\"/var/log/vmware/vsphere-ui/logs/changelog.log\"
          Tag=\"ui-changelog\"
          Severity=\"info\"
          Facility=\"local0\"
          deleteStateOnFileDelete=\"on\"
          reopenOnTruncate=\"on\")
    #vsphere-ui dataservice log
    input(type=\"imfile\"
          File=\"/var/log/vmware/vsphere-ui/logs/dataservice.log\"
          Tag=\"ui-dataservice\"
          Severity=\"info\"
          Facility=\"local0\"
          deleteStateOnFileDelete=\"on\"
          reopenOnTruncate=\"on\")
    #vsphere-ui apigw log
    input(type=\"imfile\"
          File=\"/var/log/vmware/vsphere-ui/logs/apigw.log\"
          Tag=\"ui-apigw\"
          Severity=\"info\"
          Facility=\"local0\"
          deleteStateOnFileDelete=\"on\"
          reopenOnTruncate=\"on\")
    #vsphere-ui equinox log
    input(type=\"imfile\"
          File=\"/var/log/vmware/vsphere-ui/logs/equinox.log\"
          Tag=\"ui-equinox\"
          Severity=\"info\"
          Facility=\"local0\"
          deleteStateOnFileDelete=\"on\"
          reopenOnTruncate=\"on\")
    #vsphere-ui event log
    input(type=\"imfile\"
          File=\"/var/log/vmware/vsphere-ui/logs/eventlog.log\"
          Tag=\"ui-eventlog\"
          Severity=\"info\"
          Facility=\"local0\"
          deleteStateOnFileDelete=\"on\"
          reopenOnTruncate=\"on\")
    #vsphere-ui op id log
    input(type=\"imfile\"
          File=\"/var/log/vmware/vsphere-ui/logs/opId.log\"
          Tag=\"ui-opid\"
          Severity=\"info\"
          Facility=\"local0\"
          deleteStateOnFileDelete=\"on\"
          reopenOnTruncate=\"on\")
    #vsphere-ui performance audit log
    input(type=\"imfile\"
          File=\"/var/log/vmware/vsphere-ui/logs/performanceAudit.log\"
          Tag=\"ui-performanceAudit\"
          Severity=\"info\"
          Facility=\"local0\"
          deleteStateOnFileDelete=\"on\"
          reopenOnTruncate=\"on\")
    #vsphere-ui plugin-medic log
    input(type=\"imfile\"
          File=\"/var/log/vmware/vsphere-ui/logs/plugin-medic.log\"
          Tag=\"ui-plugin-medic\"
          Severity=\"info\"
          Facility=\"local0\"
          deleteStateOnFileDelete=\"on\"
          reopenOnTruncate=\"on\")
    #vsphere-ui threadmonitor log
    input(type=\"imfile\"
          File=\"/var/log/vmware/vsphere-ui/logs/threadmonitor.log\"
          Tag=\"ui-threadmonitor\"
          Severity=\"info\"
          Facility=\"local0\"
          deleteStateOnFileDelete=\"on\"
          reopenOnTruncate=\"on\")
    #vsphere-ui threadpools log
    input(type=\"imfile\"
          File=\"/var/log/vmware/vsphere-ui/logs/threadpools.log\"
          Tag=\"ui-threadpools\"
          Severity=\"info\"
          Facility=\"local0\"
          deleteStateOnFileDelete=\"on\"
          reopenOnTruncate=\"on\")
    #vsphere-ui vspheremessaging log
    input(type=\"imfile\"
          File=\"/var/log/vmware/vsphere-ui/logs/vspheremessaging.log\"
          Tag=\"ui-vspheremessaging\"
          Severity=\"info\"
          Facility=\"local0\"
          deleteStateOnFileDelete=\"on\"
          reopenOnTruncate=\"on\")
    #vsphere-ui rpm log
    input(type=\"imfile\"
          File=\"/var/log/vmware/vsphere-ui/logs/vsphere-ui-rpm.log\"
          Tag=\"ui-rpm\"
          Severity=\"info\"
          Facility=\"local0\"
          deleteStateOnFileDelete=\"on\"
          reopenOnTruncate=\"on\")
    #vsphere-ui runtime log stdout
    input(type=\"imfile\"
          File=\"/var/log/vmware/vsphere-ui/logs/vsphere-ui-runtime.log.stdout\"
          Tag=\"ui-runtime-stdout\"
          Severity=\"info\"
          Facility=\"local0\"
          deleteStateOnFileDelete=\"on\"
          reopenOnTruncate=\"on\")
    #vsphere-ui runtime log stderr
    input(type=\"imfile\"
          File=\"/var/log/vmware/vsphere-ui/logs/vsphere-ui-runtime.log.stderr\"
          Tag=\"ui-runtime-stderr\"
          Severity=\"info\"
          Facility=\"local0\"
          deleteStateOnFileDelete=\"on\"
          reopenOnTruncate=\"on\")
    #vsphere-ui access log
    input(type=\"imfile\"
          File=\"/var/log/vmware/vsphere-ui/logs/access/localhost_access_log.txt\"
          Tag=\"ui-access\"
          Severity=\"info\"
          Facility=\"local0\"
          deleteStateOnFileDelete=\"on\"
          reopenOnTruncate=\"on\")
    #vsphere-ui gc log
    input(type=\"imfile\"
          File=\"/var/log/vmware/vsphere-ui/vsphere-ui-gc.log\"
          Tag=\"ui-gc\"
          Severity=\"info\"
          Facility=\"local0\"
          deleteStateOnFileDelete=\"on\"
          reopenOnTruncate=\"on\")
    #vsphere-ui firstboot log
    input(type=\"imfile\"
          File=\"/var/log/firstboot/vsphere_ui_firstboot*\"
          Tag=\"ui-firstboot\"
          Severity=\"info\"
          Facility=\"local0\"
          deleteStateOnFileDelete=\"on\"
          reopenOnTruncate=\"on\")
    #vsphere-ui catalina
    input(type=\"imfile\"
          File=\"/var/log/vmware/vsphere-ui/logs/catalina.*.log\"
          Tag=\"ui-runtime-catalina\"
          Severity=\"info\"
          Facility=\"local0\"
          deleteStateOnFileDelete=\"on\"
          reopenOnTruncate=\"on\")
    #vsphere-ui endpoint
    input(type=\"imfile\"
          File=\"/var/log/vmware/vsphere-ui/logs/endpoint.log\"
          Tag=\"ui-runtime-endpoint\"
          Severity=\"info\"
          Facility=\"local0\"
          deleteStateOnFileDelete=\"on\"
          reopenOnTruncate=\"on\")
    #vsphere-ui localhost
    input(type=\"imfile\"
          File=\"/var/log/vmware/vsphere-ui/logs/localhost.*.log\"
          Tag=\"ui-runtime-localhost\"
          Severity=\"info\"
          Facility=\"local0\"
          deleteStateOnFileDelete=\"on\"
          reopenOnTruncate=\"on\")
    #vsphere-ui vsan
    input(type=\"imfile\"
          File=\"/var/log/vmware/vsphere-ui/logs/vsan-plugin.log\"
          Tag=\"ui-runtime-vsan\"
          Severity=\"info\"
          Facility=\"local0\"
          deleteStateOnFileDelete=\"on\"
          reopenOnTruncate=\"on\")

    Note: If the entries for \"deleteStateOnFileDelete\" or \"reopenOnTruncate\" are not present, this is not a finding.

    If the output does not match the expected result, this is a finding.
  "
  desc 'fix', "
    Navigate to and open:

    vmware-services-vsphere-ui.conf

    Create the file if it does not exist.

    Set the contents of the file as follows:

    #vsphere-ui main log
    input(type=\"imfile\"
          File=\"/var/log/vmware/vsphere-ui/logs/vsphere_client_virgo.log\"
          Tag=\"ui-main\"
          Severity=\"info\"
          Facility=\"local0\"
          deleteStateOnFileDelete=\"on\"
          reopenOnTruncate=\"on\")
    #vsphere-ui change log
    input(type=\"imfile\"
          File=\"/var/log/vmware/vsphere-ui/logs/changelog.log\"
          Tag=\"ui-changelog\"
          Severity=\"info\"
          Facility=\"local0\"
          deleteStateOnFileDelete=\"on\"
          reopenOnTruncate=\"on\")
    #vsphere-ui dataservice log
    input(type=\"imfile\"
          File=\"/var/log/vmware/vsphere-ui/logs/dataservice.log\"
          Tag=\"ui-dataservice\"
          Severity=\"info\"
          Facility=\"local0\"
          deleteStateOnFileDelete=\"on\"
          reopenOnTruncate=\"on\")
    #vsphere-ui apigw log
    input(type=\"imfile\"
          File=\"/var/log/vmware/vsphere-ui/logs/apigw.log\"
          Tag=\"ui-apigw\"
          Severity=\"info\"
          Facility=\"local0\"
          deleteStateOnFileDelete=\"on\"
          reopenOnTruncate=\"on\")
    #vsphere-ui equinox log
    input(type=\"imfile\"
          File=\"/var/log/vmware/vsphere-ui/logs/equinox.log\"
          Tag=\"ui-equinox\"
          Severity=\"info\"
          Facility=\"local0\"
          deleteStateOnFileDelete=\"on\"
          reopenOnTruncate=\"on\")
    #vsphere-ui event log
    input(type=\"imfile\"
          File=\"/var/log/vmware/vsphere-ui/logs/eventlog.log\"
          Tag=\"ui-eventlog\"
          Severity=\"info\"
          Facility=\"local0\"
          deleteStateOnFileDelete=\"on\"
          reopenOnTruncate=\"on\")
    #vsphere-ui op id log
    input(type=\"imfile\"
          File=\"/var/log/vmware/vsphere-ui/logs/opId.log\"
          Tag=\"ui-opid\"
          Severity=\"info\"
          Facility=\"local0\"
          deleteStateOnFileDelete=\"on\"
          reopenOnTruncate=\"on\")
    #vsphere-ui performance audit log
    input(type=\"imfile\"
          File=\"/var/log/vmware/vsphere-ui/logs/performanceAudit.log\"
          Tag=\"ui-performanceAudit\"
          Severity=\"info\"
          Facility=\"local0\"
          deleteStateOnFileDelete=\"on\"
          reopenOnTruncate=\"on\")
    #vsphere-ui plugin-medic log
    input(type=\"imfile\"
          File=\"/var/log/vmware/vsphere-ui/logs/plugin-medic.log\"
          Tag=\"ui-plugin-medic\"
          Severity=\"info\"
          Facility=\"local0\"
          deleteStateOnFileDelete=\"on\"
          reopenOnTruncate=\"on\")
    #vsphere-ui threadmonitor log
    input(type=\"imfile\"
          File=\"/var/log/vmware/vsphere-ui/logs/threadmonitor.log\"
          Tag=\"ui-threadmonitor\"
          Severity=\"info\"
          Facility=\"local0\"
          deleteStateOnFileDelete=\"on\"
          reopenOnTruncate=\"on\")
    #vsphere-ui threadpools log
    input(type=\"imfile\"
          File=\"/var/log/vmware/vsphere-ui/logs/threadpools.log\"
          Tag=\"ui-threadpools\"
          Severity=\"info\"
          Facility=\"local0\"
          deleteStateOnFileDelete=\"on\"
          reopenOnTruncate=\"on\")
    #vsphere-ui vspheremessaging log
    input(type=\"imfile\"
          File=\"/var/log/vmware/vsphere-ui/logs/vspheremessaging.log\"
          Tag=\"ui-vspheremessaging\"
          Severity=\"info\"
          Facility=\"local0\"
          deleteStateOnFileDelete=\"on\"
          reopenOnTruncate=\"on\")
    #vsphere-ui rpm log
    input(type=\"imfile\"
          File=\"/var/log/vmware/vsphere-ui/logs/vsphere-ui-rpm.log\"
          Tag=\"ui-rpm\"
          Severity=\"info\"
          Facility=\"local0\"
          deleteStateOnFileDelete=\"on\"
          reopenOnTruncate=\"on\")
    #vsphere-ui runtime log stdout
    input(type=\"imfile\"
          File=\"/var/log/vmware/vsphere-ui/logs/vsphere-ui-runtime.log.stdout\"
          Tag=\"ui-runtime-stdout\"
          Severity=\"info\"
          Facility=\"local0\"
          deleteStateOnFileDelete=\"on\"
          reopenOnTruncate=\"on\")
    #vsphere-ui runtime log stderr
    input(type=\"imfile\"
          File=\"/var/log/vmware/vsphere-ui/logs/vsphere-ui-runtime.log.stderr\"
          Tag=\"ui-runtime-stderr\"
          Severity=\"info\"
          Facility=\"local0\"
          deleteStateOnFileDelete=\"on\"
          reopenOnTruncate=\"on\")
    #vsphere-ui access log
    input(type=\"imfile\"
          File=\"/var/log/vmware/vsphere-ui/logs/access/localhost_access_log.txt\"
          Tag=\"ui-access\"
          Severity=\"info\"
          Facility=\"local0\"
          deleteStateOnFileDelete=\"on\"
          reopenOnTruncate=\"on\")
    #vsphere-ui gc log
    input(type=\"imfile\"
          File=\"/var/log/vmware/vsphere-ui/vsphere-ui-gc.log\"
          Tag=\"ui-gc\"
          Severity=\"info\"
          Facility=\"local0\"
          deleteStateOnFileDelete=\"on\"
          reopenOnTruncate=\"on\")
    #vsphere-ui firstboot log
    input(type=\"imfile\"
          File=\"/var/log/firstboot/vsphere_ui_firstboot*\"
          Tag=\"ui-firstboot\"
          Severity=\"info\"
          Facility=\"local0\"
          deleteStateOnFileDelete=\"on\"
          reopenOnTruncate=\"on\")
    #vsphere-ui catalina
    input(type=\"imfile\"
          File=\"/var/log/vmware/vsphere-ui/logs/catalina.*.log\"
          Tag=\"ui-runtime-catalina\"
          Severity=\"info\"
          Facility=\"local0\"
          deleteStateOnFileDelete=\"on\"
          reopenOnTruncate=\"on\")
    #vsphere-ui endpoint
    input(type=\"imfile\"
          File=\"/var/log/vmware/vsphere-ui/logs/endpoint.log\"
          Tag=\"ui-runtime-endpoint\"
          Severity=\"info\"
          Facility=\"local0\"
          deleteStateOnFileDelete=\"on\"
          reopenOnTruncate=\"on\")
    #vsphere-ui localhost
    input(type=\"imfile\"
          File=\"/var/log/vmware/vsphere-ui/logs/localhost.*.log\"
          Tag=\"ui-runtime-localhost\"
          Severity=\"info\"
          Facility=\"local0\"
          deleteStateOnFileDelete=\"on\"
          reopenOnTruncate=\"on\")
    #vsphere-ui vsan
    input(type=\"imfile\"
          File=\"/var/log/vmware/vsphere-ui/logs/vsan-plugin.log\"
          Tag=\"ui-runtime-vsan\"
          Severity=\"info\"
          Facility=\"local0\"
          deleteStateOnFileDelete=\"on\"
          reopenOnTruncate=\"on\")
  "
  impact 0.5
  tag severity: 'medium'
  tag gtitle: 'SRG-APP-000358-AS-000064'
  tag gid: 'V-VCUI-80-000081'
  tag rid: 'SV-VCUI-80-000081'
  tag stig_id: 'VCUI-80-000081'
  tag cci: ['CCI-001851']
  tag nist: ['AU-4 (1)']

  goodcontent_v1 = inspec.profile.file('vmware-services-vsphere-ui-v1.conf')
  goodcontent_v2 = inspec.profile.file('vmware-services-vsphere-ui-v2.conf')

  describe.one do
    describe file('/etc/vmware-syslog/vmware-services-vsphere-ui.conf') do
      its('content') { should eq goodcontent_v1 }
    end
    describe file('/etc/vmware-syslog/vmware-services-vsphere-ui.conf') do
      its('content') { should eq goodcontent_v2 }
    end
  end
end
