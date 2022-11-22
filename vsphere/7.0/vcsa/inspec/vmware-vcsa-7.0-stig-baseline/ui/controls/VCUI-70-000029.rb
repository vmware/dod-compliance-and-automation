control 'VCUI-70-000029' do
  title 'vSphere UI log files must be moved to a permanent repository in accordance with site policy.'
  desc  "
    vSphere UI produces a handful of logs that must be offloaded from the originating system. This information can then be used for diagnostic, forensics, or other purposes relevant to ensuring the availability and integrity of the hosted application.

    vSphere UI syslog configuration is included by default, as part of the VMware-visl-integration package. The shipping state of the configuration file must be verified and maintained.
  "
  desc  'rationale', ''
  desc  'check', "
    At the command prompt, execute the following command:

    # rpm -V VMware-visl-integration|grep vmware-services-vsphere-ui.conf|grep \"^..5......\"

    If the command returns any output, this is a finding.
  "
  desc 'fix', "
    Navigate to and open:

    /etc/vmware-syslog/vmware-services-vsphere-ui.conf

    Create the file if it does not exist.

    Set the contents of the file as follows:

    input(type=\"imfile\"
          File=\"/var/log/vmware/vsphere-ui/logs/vsphere_client_virgo.log\"
          Tag=\"ui-main\"
          Severity=\"info\"
          Facility=\"local0\")
    input(type=\"imfile\"
          File=\"/var/log/vmware/vsphere-ui/logs/changelog.log\"
          Tag=\"ui-changelog\"
          Severity=\"info\"
          Facility=\"local0\")
    input(type=\"imfile\"
          File=\"/var/log/vmware/vsphere-ui/logs/dataservice.log\"
          Tag=\"ui-dataservice\"
          Severity=\"info\"
          Facility=\"local0\")
    input(type=\"imfile\"
          File=\"/var/log/vmware/vsphere-ui/logs/apigw.log\"
          Tag=\"ui-apigw\"
          Severity=\"info\"
          Facility=\"local0\")
    input(type=\"imfile\"
          File=\"/var/log/vmware/vsphere-ui/logs/equinox.log\"
          Tag=\"ui-equinox\"
          Severity=\"info\"
          Facility=\"local0\")
    input(type=\"imfile\"
          File=\"/var/log/vmware/vsphere-ui/logs/eventlog.log\"
          Tag=\"ui-eventlog\"
          Severity=\"info\"
          Facility=\"local0\")
    input(type=\"imfile\"
          File=\"/var/log/vmware/vsphere-ui/logs/httpRequest.log\"
          Tag=\"ui-httpRequest\"
          Severity=\"info\"
          Facility=\"local0\")
    input(type=\"imfile\"
          File=\"/var/log/vmware/vsphere-ui/logs/opid.log\"
          Tag=\"ui-opid\"
          Severity=\"info\"
          Facility=\"local0\")
    input(type=\"imfile\"
          File=\"/var/log/vmware/vsphere-ui/logs/osgi.log\"
          Tag=\"ui-osgi\"
          Severity=\"info\"
          Facility=\"local0\")
    input(type=\"imfile\"
          File=\"/var/log/vmware/vsphere-ui/logs/performanceAudit.log\"
          Tag=\"ui-performanceAudit\"
          Severity=\"info\"
          Facility=\"local0\")
    input(type=\"imfile\"
          File=\"/var/log/vmware/vsphere-ui/logs/plugin-medic.log\"
          Tag=\"ui-plugin-medic\"
          Severity=\"info\"
          Facility=\"local0\")
    input(type=\"imfile\"
          File=\"/var/log/vmware/vsphere-ui/logs/threadmonitor.log\"
          Tag=\"ui-threadmonitor\"
          Severity=\"info\"
          Facility=\"local0\")
    input(type=\"imfile\"
          File=\"/var/log/vmware/vsphere-ui/logs/threadpools.log\"
          Tag=\"ui-threadpools\"
          Severity=\"info\"
          Facility=\"local0\")
    input(type=\"imfile\"
          File=\"/var/log/vmware/vsphere-ui/logs/vspheremessaging.log\"
          Tag=\"ui-vspheremessaging\"
          Severity=\"info\"
          Facility=\"local0\")
    input(type=\"imfile\"
          File=\"/var/log/vmware/vsphere-ui/logs/vsphere-ui-rpm.log\"
          Tag=\"ui-rpm\"
          Severity=\"info\"
          Facility=\"local0\")
    input(type=\"imfile\"
          File=\"/var/log/vmware/vsphere-ui/logs/vsphere-ui-runtime*\"
          Tag=\"ui-runtime\"
          Severity=\"info\"
          Facility=\"local0\")
    input(type=\"imfile\"
          File=\"/var/log/vmware/vsphere-ui/logs/access/localhost_access*\"
          Tag=\"ui-access\"
          Severity=\"info\"
          Facility=\"local0\")
    input(type=\"imfile\"
          File=\"/var/log/vmware/vsphere-ui/vsphere-ui-gc*\"
          Tag=\"ui-gc\"
          Severity=\"info\"
          Facility=\"local0\")
    input(type=\"imfile\"
          File=\"/var/log/firstboot/vsphere_ui_firstboot*\"
          Tag=\"ui-firstboot\"
          Severity=\"info\"
          Facility=\"local0\")
  "
  impact 0.5
  tag severity: 'medium'
  tag gtitle: 'SRG-APP-000358-WSR-000163'
  tag satisfies: ['SRG-APP-000108-WSR-000166', 'SRG-APP-000125-WSR-000071']
  tag gid: nil
  tag rid: nil
  tag stig_id: 'VCUI-70-000029'
  tag cci: ['CCI-000139', 'CCI-001348', 'CCI-001851']
  tag nist: ['AU-4 (1)', 'AU-5 a', 'AU-9 (2)']

  describe command('rpm -V VMware-visl-integration|grep vmware-services-vsphere-ui.conf|grep "^..5......"') do
    its('stdout.strip') { should eq '' }
  end
end
