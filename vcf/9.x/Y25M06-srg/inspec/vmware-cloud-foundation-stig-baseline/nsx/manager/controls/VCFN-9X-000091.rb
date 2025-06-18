control 'VCFN-9X-000091' do
  title 'The VMware Cloud Foundation NSX Manager must be configured to conduct backups on an organizationally defined schedule.'
  desc  "
    Information system backup is a critical step in maintaining data assurance and availability. Information system and security-related documentation contains information pertaining to system configuration and security settings. If this information were not backed up, and a system failure were to occur, the security settings would be difficult to reconfigure quickly and accurately. Maintaining a backup of information system and security-related documentation provides for a quicker recovery time when system outages occur.

    This control requires the network device to support the organizational central backup process for user account information associated with the network device. This function may be provided by the network device itself; however, the preferred best practice is a centralized backup rather than each network device performing discrete backups.
  "
  desc  'rationale', ''
  desc  'check', "
    From the NSX Manager web interface, go to System >> Lifecycle Management >> Backup and Restore to view the backup configuration.

    If backup is not configured and scheduled on a recurring frequency, this is a finding.
  "
  desc 'fix', "
    To configure a backup destination, do the following:

    From the NSX Manager web interface, go to System >> Lifecycle Management >> Backup and Restore, and then click \"Edit\" next to SFTP Server.

    Enter the target SFTP server, Directory Path, Username, Password, SSH Fingerprint, and Passphrase, and then click \"Save\".

    To configure a backup schedule, do the following:

    From the NSX Manager web interface, go to System >> Lifecycle Management >> Backup and Restore, and then click \"Edit\" next to Schedule.

    Click the \"Recurring Backup\" toggle and configure an interval between backups.

    Enable \"Detect NSX configuration change\" to trigger backups on detection of configuration changes and specify an interval for detecting changes. Click \"Save\".
  "
  impact 0.5
  tag severity: 'medium'
  tag gtitle: 'SRG-APP-000516-NDM-000341'
  tag satisfies: ['SRG-APP-000516-NDM-000340']
  tag gid: 'V-VCFN-9X-000091'
  tag rid: 'SV-VCFN-9X-000091'
  tag stig_id: 'VCFN-9X-000091'
  tag cci: ['CCI-000366', 'CCI-000537', 'CCI-000539']
  tag nist: ['CM-6 b', 'CP-9 (b)', 'CP-9 (c)']

  result = http("https://#{input('nsx_managerAddress')}/api/v1/cluster/backups/config",
                method: 'GET',
                headers: {
                  'Accept' => 'application/json',
                  'X-XSRF-TOKEN' => "#{input('nsx_sessionToken')}",
                  'Cookie' => "#{input('nsx_sessionCookieId')}"
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
