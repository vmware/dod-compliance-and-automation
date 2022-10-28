control 'VCSA-70-000292' do
  title 'The vCenter server configuration must be backed up on a regular basis.'
  desc  "
    vCenter server is the control plane for the vSphere infrastructure and all the workloads it hosts. As such, vCenter itself is usually a highly critical system in it's own right. Backups of vCenter can now be made at a data and configuration level vs traditional storage/image-based backups. This reduces recovery time by letting the SA spin up a new vCenter while simultaneously importing the backed up data.

    For sites that implement the Native Key Provider (NKP), introduced in 7.0 Update 2, regular vCenter backups are critical. In a recovery scenario where the VM files are intact but vCenter was lost, the encrypted VMs will not be able to boot as their private keys were stored in vCenter after it was last backed up. When using the NKP, vCenter becomes critical to the VM workloads and ceases to just be the control plane.
  "
  desc  'rationale', ''
  desc  'check', "
    Option 1:

    If vCenter is backed up in a traditional manner, at the storage array level, interview the SA to determine configuration and schedule.

    Option 2:

    For vCenter native backup functionality, open the Virtual Appliance Management Interface (VAMI) by navigating to https://<vCenter server>:5480.

    Log in with local OS administrative credentials or with an SSO account that is a member of the \"SystemConfiguration.BashShellAdministrator\" group.

    Select \"Backup\" on the left navigation pane.

    On the resulting pane on the right, verify the \"Status\" is \"Enabled\".

    Click to \"Status\" expand the backup details.

    If vCenter server backups are not configured and there is no other vCenter backup system, this is a finding.

    If the backup configuration is not set to a proper, reachable location or if the schedule is anything less frequent than \"Daily\", this is a finding.
  "
  desc 'fix', "
    Option 1:

    Implement and document a VMware-supported storage/image-based backup schedule.

    Option 2:

    To configure vCenter native backup functionality, open the Virtual Appliance Management Interface (VAMI) by navigating to https://<vCenter server>:5480.

    Log in with local OS administrative credentials or with an SSO account that is a member of the \"SystemConfiguration.BashShellAdministrator\" group.

    Select \"Backup\" on the left navigation pane.

    On the resulting pane on the right, click \"Configure\" (or \"Edit\" for an existing configuration).

    Enter site-specific information for the backup job.

    Ensure that the \"Schedule\" is set to \"Daily\". Limiting the number of retained backups is recommended but not required.

    Click \"Create\".
  "
  impact 0.5
  tag severity: 'medium'
  tag gtitle: 'SRG-APP-000516'
  tag gid: nil
  tag rid: nil
  tag stig_id: 'VCSA-70-000292'
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']

  if input('backup3rdParty')
    describe 'This check is a manual or policy based check' do
      skip 'This must be reviewed manually'
    end
  else
    result = http("https://#{input('vcURL')}/api/appliance/recovery/backup/schedules",
                method: 'GET',
                headers: {
                  'vmware-api-session-id' => "#{input('vcApiToken')}",
                  },
                ssl_verify: false)

    describe result do
      its('status') { should cmp 200 }
    end
    unless result.status != 200
      describe result.body do
        it { should_not cmp '{}' }
      end
      unless result.body == '{}'
        describe json(content: result.body) do
          its(['default', 'enable']) { should cmp 'true' }
          its(['default', 'recurrence_info', 'days']) { should cmp [] }
        end
      end
    end
  end
end
