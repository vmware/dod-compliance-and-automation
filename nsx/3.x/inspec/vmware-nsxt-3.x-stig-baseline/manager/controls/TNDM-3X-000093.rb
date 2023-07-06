control 'TNDM-3X-000093' do
  title 'The NSX-T Manager must be configured to conduct backups on an organizationally defined schedule.'
  desc  "
    System-level information includes default and customized settings and security attributes, including ACLs that relate to the network device configuration, as well as software required for the execution and operation of the device. Information system backup is a critical step in ensuring system integrity and availability. If the system fails and there is no backup of the system-level information, a denial of service condition is possible for all who utilize this critical network component.

    This control requires the network device to support the organizational central backup process for system-level information associated with the network device. This function may be provided by the network device itself; however, the preferred best practice is a centralized backup rather than each network device performing discrete backups.
  "
  desc  'rationale', ''
  desc  'check', "
    From the NSX-T Manager web interface, go to System >> Backup and Restore to view the backup configuration.

    If backup is not configured and scheduled on a recurring frequency, this is a finding.
  "
  desc 'fix', "
    To configure a backup destination, do the following:

    From the NSX-T Manager web interface, go to System >> Backup and Restore, and then click \"Edit\" next to SFTP Server.

    Enter the target SFTP server, Directory Path, Username, Password, SSH Fingerprint, and Passphrase, and then click \"Save\".

    To configure a backup schedule do the following:

    From the NSX-T Manager web interface, go to System >> Backup and Restore, and then click \"Edit\" next to Schedule.

    Click the \"Recurring Backup\" toggle and configure an interval between backups. Enable \"Detect NSX configuration change\" to trigger backups on detection of configuration changes and specify an interval for detecting changes. Click \"Save\".
  "
  impact 0.5
  tag severity: 'medium'
  tag gtitle: 'SRG-APP-000516-NDM-000340'
  tag gid: 'V-251790'
  tag rid: 'SV-251790r810373_rule'
  tag stig_id: 'TNDM-3X-000093'
  tag fix_id: 'F-55204r810372_fix'
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']

  result = http("https://#{input('nsxManager')}/api/v1/cluster/backups/config",
              method: 'GET',
              headers: {
                'Accept' => 'application/json',
                'X-XSRF-TOKEN' => "#{input('sessionToken')}",
                'Cookie' => "#{input('sessionCookieId')}",
                },
              ssl_verify: false)

  describe result do
    its('status') { should cmp 200 }
  end
  unless result.status != 200
    describe json(content: result.body) do
      its('backup_enabled') { should cmp 'true' }
      its(['backup_schedule', 'resource_type']) { should be_in ['IntervalBackupSchedule', 'WeeklyBackupSchedule'] }
    end
  end
end
