control 'VCLD-80-000022' do
  title 'The vCenter VAMI service must off-load log records onto a different system or media from the system being logged.'
  desc 'Protection of log data includes assuring log data is not accidentally lost or deleted. Backing up log records to an unrelated system or onto separate media than the system the web server is actually running on helps to assure that, in the event of a catastrophic system failure, the log records will be retained.'
  desc 'check', 'By default there is a vmware-services-applmgmt.conf rsyslog configuration file which includes the service logs when syslog is configured on vCenter that must be verified.

At the command prompt, run the following command:

# cat /etc/vmware-syslog/vmware-services-applmgmt.conf

Expected result:

#applmgmt.log
input(type="imfile"
      File="/var/log/vmware/applmgmt/applmgmt.log"
      Tag="applmgmt"
      Severity="info"
      Facility="local0")
#applmgmt-audit.log
input(type="imfile"
      File="/var/log/vmware/applmgmt-audit/applmgmt-audit.log"
      Tag="applmgmt-audit"
      Severity="info"
      Facility="local0")
#applmgmt-backup-restore-audit.log
input(type="imfile"
      File="/var/log/vmware/applmgmt-audit/applmgmt-br-audit.log"
      Tag="applmgmt-br-audit"
      Severity="info"
      Facility="local0")
#vami-access.log
input(type="imfile"
      File="/opt/vmware/var/log/lighttpd/access.log"
      Tag="vami-access"
      Severity="info"
      Facility="local0")
#vami-error.log
input(type="imfile"
      File="/opt/vmware/var/log/lighttpd/error.log"
      Tag="vami-error"
      Severity="info"
      Facility="local0")
#dcui.log
input(type="imfile"
      File="/var/log/vmware/applmgmt/dcui.log"
      Tag="dcui"
      Severity="info"
      Facility="local0")
#detwist.log
input(type="imfile"
      File="/var/log/vmware/applmgmt/detwist.log"
      Tag="detwist"
      Severity="info"
      Facility="local0")
#firewall-reload.log
input(type="imfile"
      File="/var/log/vmware/applmgmt/firewall-reload.log"
      Tag="firewall-reload"
      Severity="info"
      Facility="local0")
#applmgmt_vmonsvc.std*
input(type="imfile"
      File="/var/log/vmware/applmgmt/applmgmt_vmonsvc.std*"
      Tag="applmgmt_vmonsvc"
      Severity="info"
      Facility="local0")
#backupSchedulerCron
input(type="imfile"
      File="/var/log/vmware/applmgmt/backupSchedulerCron.log"
      Tag="backupSchedulerCron"
      Severity="info"
      Facility="local0")
#progress.log
input(type="imfile"
      File="/var/log/vmware/applmgmt/progress.log"
      Tag="progress"
      Severity="info"
      Facility="local0")
#statsmoitor-alarms
input(type="imfile"
      File="/var/log/vmware/statsmon/statsmoitor-alarms.log"
      Tag="statsmoitor-alarms"
      Severity="info"
      Facility="local0")
#StatsMonitor
input(type="imfile"
      File="/var/log/vmware/statsmon/StatsMonitor.log"
      Tag="StatsMonitor"
      Severity="info"
      Facility="local0")
#StatsMonitorStartup.log.std*
input(type="imfile"
      File="/var/log/vmware/statsmon/StatsMonitorStartup.log.std*"
      Tag="StatsMonitor-Startup"
      Severity="info"
      Facility="local0")
#PatchRunner
input(type="imfile"
      File="/var/log/vmware/applmgmt/PatchRunner.log"
      Tag="PatchRunner"
      Severity="info"
      Facility="local0")
#update_microservice
input(type="imfile"
      File="/var/log/vmware/applmgmt/update_microservice.log"
      Tag="update_microservice"
      Severity="info"
      Facility="local0")
#vami
input(type="imfile"
      File="/var/log/vmware/applmgmt/vami.log"
      Tag="vami"
      Severity="info"
      Facility="local0")
#vcdb_pre_patch
input(type="imfile"
      File="/var/log/vmware/applmgmt/vcdb_pre_patch.*"
      Tag="vcdb_pre_patch"
      Severity="info"
      Facility="local0")
#dnsmasq.log
input(type="imfile"
      File="/var/log/vmware/dnsmasq.log"
      Tag="dnsmasq"
      Severity="info"
      Facility="local0")
#procstate
input(type="imfile"
      File="/var/log/vmware/procstate"
      Tag="procstate"
      Severity="info"
      Facility="local0")
#backup.log
input(type="imfile"
      File="/var/log/vmware/applmgmt/backup.log"
      Tag="applmgmt-backup"
      Severity="info"
      Facility="local0")
#size.log
input(type="imfile"
      File="/var/log/vmware/applmgmt/size.log"
      Tag="applmgmt-size"
      Severity="info"
      Facility="local0")
#restore.log
input(type="imfile"
      File="/var/log/vmware/applmgmt/restore.log"
      Tag="applmgmt-restore"
      Severity="info"
      Facility="local0")
#reconciliation.log
input(type="imfile"
      File="/var/log/vmware/applmgmt/reconciliation.log"
      Tag="applmgmt-reconciliation"
      Severity="info"
      Facility="local0")
#pnid_change.log
input(type="imfile"
      File="/var/log/vmware/applmgmt/pnid_change.log"
      Tag="applmgmt-pnid-change"
      Severity="info"
      Facility="local0")

If the output does not match the expected result, this is a finding.'
  desc 'fix', 'Navigate to and open:

/etc/vmware-syslog/vmware-services-applmgmt.conf

Create the file if it does not exist.

Set the contents of the file as follows:

#applmgmt.log
input(type="imfile"
      File="/var/log/vmware/applmgmt/applmgmt.log"
      Tag="applmgmt"
      Severity="info"
      Facility="local0")
#applmgmt-audit.log
input(type="imfile"
      File="/var/log/vmware/applmgmt-audit/applmgmt-audit.log"
      Tag="applmgmt-audit"
      Severity="info"
      Facility="local0")
#applmgmt-backup-restore-audit.log
input(type="imfile"
      File="/var/log/vmware/applmgmt-audit/applmgmt-br-audit.log"
      Tag="applmgmt-br-audit"
      Severity="info"
      Facility="local0")
#vami-access.log
input(type="imfile"
      File="/opt/vmware/var/log/lighttpd/access.log"
      Tag="vami-access"
      Severity="info"
      Facility="local0")
#vami-error.log
input(type="imfile"
      File="/opt/vmware/var/log/lighttpd/error.log"
      Tag="vami-error"
      Severity="info"
      Facility="local0")
#dcui.log
input(type="imfile"
      File="/var/log/vmware/applmgmt/dcui.log"
      Tag="dcui"
      Severity="info"
      Facility="local0")
#detwist.log
input(type="imfile"
      File="/var/log/vmware/applmgmt/detwist.log"
      Tag="detwist"
      Severity="info"
      Facility="local0")
#firewall-reload.log
input(type="imfile"
      File="/var/log/vmware/applmgmt/firewall-reload.log"
      Tag="firewall-reload"
      Severity="info"
      Facility="local0")
#applmgmt_vmonsvc.std*
input(type="imfile"
      File="/var/log/vmware/applmgmt/applmgmt_vmonsvc.std*"
      Tag="applmgmt_vmonsvc"
      Severity="info"
      Facility="local0")
#backupSchedulerCron
input(type="imfile"
      File="/var/log/vmware/applmgmt/backupSchedulerCron.log"
      Tag="backupSchedulerCron"
      Severity="info"
      Facility="local0")
#progress.log
input(type="imfile"
      File="/var/log/vmware/applmgmt/progress.log"
      Tag="progress"
      Severity="info"
      Facility="local0")
#statsmoitor-alarms
input(type="imfile"
      File="/var/log/vmware/statsmon/statsmoitor-alarms.log"
      Tag="statsmoitor-alarms"
      Severity="info"
      Facility="local0")
#StatsMonitor
input(type="imfile"
      File="/var/log/vmware/statsmon/StatsMonitor.log"
      Tag="StatsMonitor"
      Severity="info"
      Facility="local0")
#StatsMonitorStartup.log.std*
input(type="imfile"
      File="/var/log/vmware/statsmon/StatsMonitorStartup.log.std*"
      Tag="StatsMonitor-Startup"
      Severity="info"
      Facility="local0")
#PatchRunner
input(type="imfile"
      File="/var/log/vmware/applmgmt/PatchRunner.log"
      Tag="PatchRunner"
      Severity="info"
      Facility="local0")
#update_microservice
input(type="imfile"
      File="/var/log/vmware/applmgmt/update_microservice.log"
      Tag="update_microservice"
      Severity="info"
      Facility="local0")
#vami
input(type="imfile"
      File="/var/log/vmware/applmgmt/vami.log"
      Tag="vami"
      Severity="info"
      Facility="local0")
#vcdb_pre_patch
input(type="imfile"
      File="/var/log/vmware/applmgmt/vcdb_pre_patch.*"
      Tag="vcdb_pre_patch"
      Severity="info"
      Facility="local0")
#dnsmasq.log
input(type="imfile"
      File="/var/log/vmware/dnsmasq.log"
      Tag="dnsmasq"
      Severity="info"
      Facility="local0")
#procstate
input(type="imfile"
      File="/var/log/vmware/procstate"
      Tag="procstate"
      Severity="info"
      Facility="local0")
#backup.log
input(type="imfile"
      File="/var/log/vmware/applmgmt/backup.log"
      Tag="applmgmt-backup"
      Severity="info"
      Facility="local0")
#size.log
input(type="imfile"
      File="/var/log/vmware/applmgmt/size.log"
      Tag="applmgmt-size"
      Severity="info"
      Facility="local0")
#restore.log
input(type="imfile"
      File="/var/log/vmware/applmgmt/restore.log"
      Tag="applmgmt-restore"
      Severity="info"
      Facility="local0")
#reconciliation.log
input(type="imfile"
      File="/var/log/vmware/applmgmt/reconciliation.log"
      Tag="applmgmt-reconciliation"
      Severity="info"
      Facility="local0")
#pnid_change.log
input(type="imfile"
      File="/var/log/vmware/applmgmt/pnid_change.log"
      Tag="applmgmt-pnid-change"
      Severity="info"
      Facility="local0")'
  impact 0.5
  tag check_id: 'C-62882r935328_chk'
  tag severity: 'medium'
  tag gid: 'V-259142'
  tag rid: 'SV-259142r935330_rule'
  tag stig_id: 'VCLD-80-000022'
  tag gtitle: 'SRG-APP-000125-WSR-000071'
  tag fix_id: 'F-62791r935329_fix'
  tag satisfies: ['SRG-APP-000125-WSR-000071', 'SRG-APP-000358-WSR-000063', 'SRG-APP-000358-WSR-000163']
  tag cci: ['CCI-001348', 'CCI-001851']
  tag nist: ['AU-9 (2)', 'AU-4 (1)']

  goodcontent = inspec.profile.file('vmware-services-applmgmt.conf')
  describe file('/etc/vmware-syslog/vmware-services-applmgmt.conf') do
    its('content') { should eq goodcontent }
  end
end
