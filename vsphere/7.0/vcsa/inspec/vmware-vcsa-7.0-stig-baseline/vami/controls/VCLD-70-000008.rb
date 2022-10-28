control 'VCLD-70-000008' do
  title 'Rsyslog must be configured to monitor VAMI logs.'
  desc  "
    For performance reasons, rsyslog file monitoring is preferred over configuring VAMI to send events to a syslog facility. Without ensuring that logs are created, that rsyslog configs are created, that those configs are loaded, the log file monitoring and shipping will not be effective.

    VAMI syslog configuration is included by default, as part of the VMware-visl-integration package. The shipping state of the configuration file must be verified and maintained.
  "
  desc  'rationale', ''
  desc  'check', "
    At the command prompt, execute the following command:

    # rpm -V VMware-visl-integration|grep vmware-services-applmgmt.conf

    If the command returns any output, this is a finding.
  "
  desc 'fix', "
    Navigate to and open:

    /etc/vmware-syslog/vmware-services-applmgmt.conf

    Create the file if it does not exist.

    Set the contents of the file as follows:

    #applmgmt.log
    input(type=\"imfile\"
          File=\"/var/log/vmware/applmgmt/applmgmt.log\"
          Tag=\"applmgmt\"
          Severity=\"info\"
          Facility=\"local0\")
    #applmgmt-audit.log
    input(type=\"imfile\"
          File=\"/var/log/vmware/applmgmt-audit/applmgmt-audit.log\"
          Tag=\"applmgmt-audit\"
          Severity=\"info\"
          Facility=\"local0\")
    #applmgmt-backup-restore-audit.log
    input(type=\"imfile\"
          File=\"/var/log/vmware/applmgmt-audit/applmgmt-br-audit.log\"
          Tag=\"applmgmt-br-audit\"
          Severity=\"info\"
          Facility=\"local0\")
    #vami-access.log
    input(type=\"imfile\"
          File=\"/opt/vmware/var/log/lighttpd/access.log\"
          Tag=\"vami-access\"
          Severity=\"info\"
          Facility=\"local0\")
    #vami-error.log
    input(type=\"imfile\"
          File=\"/opt/vmware/var/log/lighttpd/error.log\"
          Tag=\"vami-error\"
          Severity=\"info\"
          Facility=\"local0\")
    #dcui.log
    input(type=\"imfile\"
          File=\"/var/log/vmware/applmgmt/dcui.log\"
          Tag=\"dcui\"
          Severity=\"info\"
          Facility=\"local0\")
    #detwist.log
    input(type=\"imfile\"
          File=\"/var/log/vmware/applmgmt/detwist.log\"
          Tag=\"detwist\"
          Severity=\"info\"
          Facility=\"local0\")
    #firewall-reload.log
    input(type=\"imfile\"
          File=\"/var/log/vmware/applmgmt/firewall-reload.log\"
          Tag=\"firewall-reload\"
          Severity=\"info\"
          Facility=\"local0\")
    #applmgmt_vmonsvc.std*
    input(type=\"imfile\"
          File=\"/var/log/vmware/applmgmt/applmgmt_vmonsvc.std*\"
          Tag=\"applmgmt_vmonsvc\"
          Severity=\"info\"
          Facility=\"local0\")
    #backupSchedulerCron
    input(type=\"imfile\"
          File=\"/var/log/vmware/applmgmt/backupSchedulerCron.log\"
          Tag=\"backupSchedulerCron\"
          Severity=\"info\"
          Facility=\"local0\")
    #progress.log
    input(type=\"imfile\"
          File=\"/var/log/vmware/applmgmt/progress.log\"
          Tag=\"progress\"
          Severity=\"info\"
          Facility=\"local0\")
    #statsmoitor-alarms
    input(type=\"imfile\"
          File=\"/var/log/vmware/applmgmt/statsmoitor-alarms.log\"
          Tag=\"statsmoitor-alarms\"
          Severity=\"info\"
          Facility=\"local0\")
    #StatsMonitor
    input(type=\"imfile\"
          File=\"/var/log/vmware/applmgmt/StatsMonitor.log\"
          Tag=\"StatsMonitor\"
          Severity=\"info\"
          Facility=\"local0\")
    #StatsMonitorStartup.log.std*
    input(type=\"imfile\"
          File=\"/var/log/vmware/applmgmt/StatsMonitorStartup.log.std*\"
          Tag=\"StatsMonitor-Startup\"
          Severity=\"info\"
          Facility=\"local0\")
    #PatchRunner
    input(type=\"imfile\"
          File=\"/var/log/vmware/applmgmt/PatchRunner.log\"
          Tag=\"PatchRunner\"
          Severity=\"info\"
          Facility=\"local0\")
    #update_microservice
    input(type=\"imfile\"
          File=\"/var/log/vmware/applmgmt/update_microservice.log\"
          Tag=\"update_microservice\"
          Severity=\"info\"
          Facility=\"local0\")
    #vami
    input(type=\"imfile\"
          File=\"/var/log/vmware/applmgmt/vami.log\"
          Tag=\"vami\"
          Severity=\"info\"
          Facility=\"local0\")
    #vcdb_pre_patch
    input(type=\"imfile\"
          File=\"/var/log/vmware/applmgmt/vcdb_pre_patch.*\"
          Tag=\"vcdb_pre_patch\"
          Severity=\"info\"
          Facility=\"local0\")
    #dnsmasq.log
    input(type=\"imfile\"
          File=\"/var/log/vmware/dnsmasq.log\"
          Tag=\"dnsmasq\"
          Severity=\"info\"
          Facility=\"local0\")
    #procstate
    input(type=\"imfile\"
          File=\"/var/log/vmware/procstate\"
          Tag=\"procstate\"
          Severity=\"info\"
          Facility=\"local0\")
    #backup.log
    input(type=\"imfile\"
          File=\"/var/log/vmware/applmgmt/backup.log\"
          Tag=\"applmgmt-backup\"
          Severity=\"info\"
          Facility=\"local0\")
    #size.log
    input(type=\"imfile\"
          File=\"/var/log/vmware/applmgmt/size.log\"
          Tag=\"applmgmt-size\"
          Severity=\"info\"
          Facility=\"local0\")
    #restore.log
    input(type=\"imfile\"
          File=\"/var/log/vmware/applmgmt/restore.log\"
          Tag=\"applmgmt-restore\"
          Severity=\"info\"
          Facility=\"local0\")
    #reconciliation.log
    input(type=\"imfile\"
          File=\"/var/log/vmware/applmgmt/reconciliation.log\"
          Tag=\"applmgmt-reconciliation\"
          Severity=\"info\"
          Facility=\"local0\")
    #pnid_change.log
    input(type=\"imfile\"
          File=\"/var/log/vmware/applmgmt/pnid_change.log\"
          Tag=\"applmgmt-pnid-change\"
          Severity=\"info\"
          Facility=\"local0\")
          File=\"/opt/vmware/var/log/lighttpd/error.log\"
          Tag=\"vami-error\"
          Severity=\"info\"
          Facility=\"local0\")
    input(type=\"imfile\"
          File=\"/var/log/vmware/applmgmt/dcui.log\"
          Tag=\"dcui\"
          Severity=\"info\"
          Facility=\"local0\")
    input(type=\"imfile\"
          File=\"/var/log/vmware/applmgmt/detwist.log\"
          Tag=\"detwist\"
          Severity=\"info\"
          Facility=\"local0\")
    input(type=\"imfile\"
          File=\"/var/log/vmware/applmgmt/firewall-reload.log\"
          Tag=\"firewall-reload\"
          Severity=\"info\"
          Facility=\"local0\")
    input(type=\"imfile\"
          File=\"/var/log/vmware/applmgmt/applmgmt_vmonsvc.std*\"
          Tag=\"applmgmt_vmonsvc\"
          Severity=\"info\"
          Facility=\"local0\")
    input(type=\"imfile\"
          File=\"/var/log/vmware/applmgmt/backupSchedulerCron.log\"
          Tag=\"backupSchedulerCron\"
          Severity=\"info\"
          Facility=\"local0\")
    input(type=\"imfile\"
          File=\"/var/log/vmware/applmgmt/progress.log\"
          Tag=\"progress\"
          Severity=\"info\"
          Facility=\"local0\")
    input(type=\"imfile\"
          File=\"/var/log/vmware/applmgmt/statsmoitor-alarms.log\"
          Tag=\"statsmoitor-alarms\"
          Severity=\"info\"
          Facility=\"local0\")
    input(type=\"imfile\"
          File=\"/var/log/vmware/applmgmt/StatsMonitor.log\"
          Tag=\"StatsMonitor\"
          Severity=\"info\"
          Facility=\"local0\")
    input(type=\"imfile\"
          File=\"/var/log/vmware/applmgmt/StatsMonitorStartup.log.std*\"
          Tag=\"StatsMonitor-Startup\"
          Severity=\"info\"
          Facility=\"local0\")
    input(type=\"imfile\"
          File=\"/var/log/vmware/applmgmt/PatchRunner.log\"
          Tag=\"PatchRunner\"
          Severity=\"info\"
          Facility=\"local0\")
    input(type=\"imfile\"
          File=\"/var/log/vmware/applmgmt/update_microservice.log\"
          Tag=\"update_microservice\"
          Severity=\"info\"
          Facility=\"local0\")
    input(type=\"imfile\"
          File=\"/var/log/vmware/applmgmt/vami.log\"
          Tag=\"vami\"
          Severity=\"info\"
          Facility=\"local0\")
    input(type=\"imfile\"
          File=\"/var/log/vmware/applmgmt/vcdb_pre_patch.*\"
          Tag=\"vcdb_pre_patch\"
          Severity=\"info\"
          Facility=\"local0\")
    input(type=\"imfile\"
          File=\"/var/log/vmware/dnsmasq.log\"
          Tag=\"dnsmasq\"
          Severity=\"info\"
          Facility=\"local0\")
    input(type=\"imfile\"
          File=\"/var/log/vmware/procstate\"
          Tag=\"procstate\"
          Severity=\"info\"
          Facility=\"local0\")
    input(type=\"imfile\"
          File=\"/var/log/vmware/applmgmt/backup.log\"
          Tag=\"applmgmt-backup\"
          Severity=\"info\"
          Facility=\"local0\")
    input(type=\"imfile\"
          File=\"/var/log/vmware/applmgmt/size.log\"
          Tag=\"applmgmt-size\"
          Severity=\"info\"
          Facility=\"local0\")
    input(type=\"imfile\"
          File=\"/var/log/vmware/applmgmt/restore.log\"
          Tag=\"applmgmt-restore\"
          Severity=\"info\"
          Facility=\"local0\")
    input(type=\"imfile\"
          File=\"/var/log/vmware/applmgmt/reconciliation.log\"
          Tag=\"applmgmt-reconciliation\"
          Severity=\"info\"
          Facility=\"local0\")
    input(type=\"imfile\"
          File=\"/var/log/vmware/applmgmt/pnid_change.log\"
          Tag=\"applmgmt-pnid-change\"
          Severity=\"info\"
          Facility=\"local0\")
  "
  impact 0.5
  tag severity: 'medium'
  tag gtitle: 'SRG-APP-000125-WSR-000071'
  tag satisfies: ['SRG-APP-000358-WSR-000063', 'SRG-APP-000358-WSR-000163']
  tag gid: nil
  tag rid: nil
  tag stig_id: 'VCLD-70-000008'
  tag cci: ['CCI-001348', 'CCI-001851']
  tag nist: ['AU-4 (1)', 'AU-9 (2)']

  describe command('rpm -V VMware-visl-integration|grep vmware-services-applmgmt.conf|grep "^..5......"') do
    its('stdout.strip') { should eq '' }
  end
end
