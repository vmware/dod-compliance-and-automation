control 'VLMA-8X-000005' do
  title 'VMware Aria Suite Lifecycle must off-load log records to a different system.'
  desc  'Information system logging capability is critical for accurate forensic analysis. Off-loading is a common process in information systems with limited log storage capacity.'
  desc  'rationale', ''
  desc  'check', "
    VMware Aria Suite Lifecycle utilizes the Aria Operations for Logs Agent to off-load logs to a syslog server or Aria Operations for Logs server.

    Log in to the VMware Aria Suite Lifecycle management interface.

    Select \"Lifecycle Operations\" >> Settings >> System Administration >> Logs.

    If the Operations for Logs Agent Configuration is not configured to off-load logs to a different system, this is a finding.
  "
  desc  'fix', "
    Log in to the VMware Aria Suite Lifecycle management interface.

    Select \"Lifecycle Operations\" >> Settings >> System Administration >> Logs.

    Enter valid information for Hostname and Port, then choose the relevant Server Protocol and fill in the remaining information.

    Click Save.
  "
  impact 0.5
  tag severity: 'medium'
  tag gtitle: 'SRG-APP-000358-AS-000064'
  tag satisfies: %w(SRG-APP-000125-AS-000084 SRG-APP-000515-AS-000203)
  tag gid: 'V-VLMA-8X-000005'
  tag rid: 'SV-VLMA-8X-000005'
  tag stig_id: 'VLMA-8X-000005'
  tag cci: %w(CCI-001348 CCI-001851)
  tag nist: ['AU-4 (1)', 'AU-9 (2)']

  describe 'This check is a manual or policy based check' do
    skip 'This must be reviewed manually'
  end
end
