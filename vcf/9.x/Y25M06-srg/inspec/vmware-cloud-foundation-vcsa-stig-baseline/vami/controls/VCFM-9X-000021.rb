control 'VCFM-9X-000021' do
  title 'The VMware Cloud Foundation vCenter VAMI Lighttpd service must off-load log records onto a different system or media from the system being logged.'
  desc  'Protection of log data includes assuring log data is not accidentally lost or deleted. Backing up log records to an unrelated system or onto separate media than the system the web server is actually running on helps to ensure that, in the event of a catastrophic system failure, the log records will be retained.'
  desc  'rationale', ''
  desc  'check', "
    By default there is a vmware-services-applmgmt.conf rsyslog configuration file which includes the service logs when syslog is configured on vCenter that must be verified.

    At the command prompt, run the following command:

    # cat /etc/vmware-syslog/vmware-services-applmgmt.conf

    Expected result:

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
          File=\"/var/log/lighttpd/access.log\"
          Tag=\"vami-access\"
          Severity=\"info\"
          Facility=\"local0\")
    #vami-error.log
    input(type=\"imfile\"
          File=\"/var/log/lighttpd/error.log\"
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
          File=\"/var/log/vmware/statsmon/statsmoitor-alarms.log\"
          Tag=\"statsmoitor-alarms\"
          Severity=\"info\"
          Facility=\"local0\")
    #StatsMonitor
    input(type=\"imfile\"
          File=\"/var/log/vmware/statsmon/StatsMonitor.log\"
          Tag=\"StatsMonitor\"
          Severity=\"info\"
          Facility=\"local0\")
    #StatsMonitorStartup.log.std*
    input(type=\"imfile\"
          File=\"/var/log/vmware/statsmon/StatsMonitorStartup.log.std*\"
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

    If the output does not match the expected result, this is a finding.
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
          File=\"/var/log/lighttpd/access.log\"
          Tag=\"vami-access\"
          Severity=\"info\"
          Facility=\"local0\")
    #vami-error.log
    input(type=\"imfile\"
          File=\"/var/log/lighttpd/error.log\"
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
          File=\"/var/log/vmware/statsmon/statsmoitor-alarms.log\"
          Tag=\"statsmoitor-alarms\"
          Severity=\"info\"
          Facility=\"local0\")
    #StatsMonitor
    input(type=\"imfile\"
          File=\"/var/log/vmware/statsmon/StatsMonitor.log\"
          Tag=\"StatsMonitor\"
          Severity=\"info\"
          Facility=\"local0\")
    #StatsMonitorStartup.log.std*
    input(type=\"imfile\"
          File=\"/var/log/vmware/statsmon/StatsMonitorStartup.log.std*\"
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
  "
  impact 0.5
  tag severity: 'medium'
  tag gtitle: 'SRG-APP-000125-WSR-000071'
  tag satisfies: ['SRG-APP-000108-WSR-000166', 'SRG-APP-000358-WSR-000063', 'SRG-APP-000358-WSR-000163', 'SRG-APP-000745-WSR-000120', 'SRG-APP-000795-WSR-000130', 'SRG-APP-000805-WSR-000140']
  tag gid: 'V-VCFM-9X-000021'
  tag rid: 'SV-VCFM-9X-000021'
  tag stig_id: 'VCFM-9X-000021'
  tag cci: ['CCI-000139', 'CCI-001348', 'CCI-001851', 'CCI-003821', 'CCI-003831', 'CCI-003938']
  tag nist: ['AU-4 (1)', 'AU-5 a', 'AU-6 (4)', 'AU-9 (2)', 'AU-9 b', 'CM-5 (1) (b)']

  goodcontent = inspec.profile.file('vmware-services-applmgmt.conf')
  describe file('/etc/vmware-syslog/vmware-services-applmgmt.conf') do
    its('content') { should eq goodcontent }
  end
end
