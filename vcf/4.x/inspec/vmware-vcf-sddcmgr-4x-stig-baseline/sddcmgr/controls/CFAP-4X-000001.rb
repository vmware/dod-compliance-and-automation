control 'CFAP-4X-000001' do
  title 'SDDC Manager must be able to be restored to the last known good configuration.'
  desc  "
    It is critically important that you back up the SDDC Manager regularly to avoid downtime and data loss in case of a system failure.

    You can back up and restore SDDC Manager with an image-based or a file-based solution. File-based backup is recommended for customers who are comfortable with configuring backups using APIs, and are not using composable servers or stretched clusters.
  "
  desc  'rationale', ''
  desc  'check', "
    For image based backups:

    Interview the SA and determine if regular image based backups are being taken of the SDDC Manager appliance.

    For file based backups:

    Check that an external SFTP server is registered with SDDC Manager.

    From the SDDC Manager UI navigate to Administration >> Backup >> Site Settings and verify an external SFTP server is configured.

    Check that a backup schedule has been configured.

    From the SDDC Manager UI navigate to Administration >> Backup >> SDDC Manager Configurations and review the backup configuration.

    or

    From a command prompt, run the following command:

    $ curl 'https://sddc-manager.sfo01.rainpole.local/v1/system/backup-configuration' -i -X GET -H 'Authorization: Bearer etYWRta....'

    Note: The SDDC manager URL and bearer token must be replaced in the example.

    If file based backups are used and an external SFTP server is not configured, this is a finding.

    If file based backups are used and an automatic backup schedule is not configured, this is a finding.

    If image based backups are used and not being performed on a regular basis, this is a finding.
  "
  desc 'fix', "
    Image based backups:

    For an image-based backup of the SDDC Manager, use a solution compatible with the VMware vSphere Storage APIs - Data Protection (formerly known as VMware vStorage APIs for Data Protection or VADP).

    For an SDDC Manager backup, connect your backup with the management domain vCenter Server.

    Configure the product to take non-quiesced backups of SDDC Manager.

    File based backups:

    Configure an external SFTP server as a target backup location.

    From the SDDC Manager UI navigate to Administration >> Backup >> Site Settings and click Register External.

    Provide the necessary information such as IP address, credentials, directory, and pass phrase and save.

    Configure a backup schedule.

    From the SDDC Manager UI navigate to Administration >> Backup >> SDDC Manager Configurations and click Edit next to Backup Schedule.

    Fill out the parameters for the backup schedule and click Save.
  "
  impact 0.5
  tag severity: 'medium'
  tag gtitle: 'SRG-APP-000133-AS-000093'
  tag gid: nil
  tag rid: nil
  tag stig_id: 'CFAP-4X-000001'
  tag cci: ['CCI-001190']
  tag nist: ['SC-24']

  sftpBackupsEnabled = input('sftpBackupsEnabled')
  sftpServer = input('sftpServer')

  if sftpBackupsEnabled
    result = http("https://#{input('sddcManager')}/v1/system/backup-configuration",
                method: 'GET',
                headers: {
                  'Accept' => 'application/json',
                  'Authorization' => "#{input('bearerToken')}",
                  },
                ssl_verify: false)

    describe result do
      its('status') { should cmp 200 }
    end
    unless result.status != 200
      describe json(content: result.body) do
        its(['backupLocations', 0, 'server']) { should cmp sftpServer }
        its(['backupSchedules', 0]) { should_not be nil }
      end
    end
  else
    describe 'SFTP Backups not in use...skipping' do
      skip 'SFTP Backups not in use...skipping'
    end
  end
end
