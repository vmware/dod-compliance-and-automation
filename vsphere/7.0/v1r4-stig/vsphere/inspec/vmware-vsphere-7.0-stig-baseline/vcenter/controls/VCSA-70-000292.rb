control 'VCSA-70-000292' do
  title 'The vCenter server configuration must be backed up on a regular basis.'
  desc 'vCenter server is the control plane for the vSphere infrastructure and all the workloads it hosts. As such, vCenter is usually a highly critical system in its own right. Backups of vCenter can now be made at a data and configuration level versus traditional storage/image-based backups. This reduces recovery time by letting the system administrator (SA) spin up a new vCenter while simultaneously importing the backed-up data.

For sites that implement the Native Key Provider (NKP), introduced in 7.0 Update 2, regular vCenter backups are critical. In a recovery scenario where the virtual machine files are intact but vCenter was lost, the encrypted virtual machines will not be able to boot as their private keys were stored in vCenter after it was last backed up. When using the NKP, vCenter becomes critical to the virtual machine workloads and ceases to be just the control plane.'
  desc 'check', 'Option 1:

If vCenter is backed up in a traditional manner, at the storage array level, interview the SA to determine configuration and schedule.

Option 2:

For vCenter native backup functionality, open the Virtual Appliance Management Interface (VAMI) by navigating to https://<vCenter server>:5480.

Log in with local operating system administrative credentials or with a Single Sign-On (SSO) account that is a member of the "SystemConfiguration.BashShellAdministrator" group.

Select "Backup" on the left navigation pane.

On the resulting pane on the right, verify the "Status" is "Enabled".

Click "Status" to expand the backup details.

If vCenter server backups are not configured and there is no other vCenter backup system, this is a finding.

If the backup configuration is not set to a proper, reachable location or if the schedule is anything less frequent than "Daily", this is a finding.'
  desc 'fix', 'Option 1:

Implement and document a VMware-supported storage/image-based backup schedule.

Option 2:

To configure vCenter native backup functionality, open the VAMI by navigating to https://<vCenter server>:5480.

Log in with local operating system administrative credentials or with an SSO account that is a member of the "SystemConfiguration.BashShellAdministrator" group.

Select "Backup" on the left navigation pane.

On the resulting pane on the right, click "Configure" (or "Edit" for an existing configuration).

Enter site-specific information for the backup job.

Ensure "Schedule" is set to "Daily". Limiting the number of retained backups is recommended but not required.

Click "Create".'
  impact 0.5
  tag check_id: 'C-60047r885725_chk'
  tag severity: 'medium'
  tag gid: 'V-256372'
  tag rid: 'SV-256372r885727_rule'
  tag stig_id: 'VCSA-70-000292'
  tag gtitle: 'SRG-APP-000516'
  tag fix_id: 'F-59990r885726_fix'
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']

  if input('backup3rdParty')
    describe '3rd party backups indicated. This check is a manual or policy based check and must be reviewed manually.' do
      skip '3rd party backups indicated. This check is a manual or policy based check and must be reviewed manually.'
    end
  else
    command = '(Invoke-ListRecoveryBackupSchedules).default.enable'
    backupsenabled = powercli_command(command).stdout.strip

    describe 'File based backups should be enabled.' do
      subject { backupsenabled }
      it { should cmp 'true' }
    end

    if backupsenabled == 'True'
      # check that backups are scheduled daily. if so the days configuration will be empty
      # if a custom schedule is specified and every day is selected this will fail and that should be changed to daily
      backupschedule = powercli_command('(Invoke-ListRecoveryBackupSchedules).default.recurrence_info.days').stdout.strip
      describe 'Backups should be scheduled daily.' do
        subject { backupschedule }
        it { should cmp '' }
      end
    end
  end
end
