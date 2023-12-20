control 'VLIA-8X-000009' do
  title 'VMware Aria Operations for Logs must alert administrators of audit failure events.'
  desc  "
    It is critical for the appropriate personnel to be aware if a system is at risk of failing to process audit logs as required. Without a real-time alert, security personnel may be unaware of an impending failure of the audit function and application operation may be adversely affected.

    Alerts provide organizations with urgent messages. Real-time alerts provide these messages immediately (i.e., the time from event detection to alert occurs in seconds or less). User-configurable controls on the Central Log Server help avoid generating excessive numbers of alert messages. Define realistic alerting limits and thresholds to avoid creating excessive numbers of alerts for noncritical events.

    This requirement must be mapped to the severity levels used by the system to denote a failure, active attack, attack involving multiple systems, and other critical notifications, at a minimum. However, note that the IDS/IDPS and other monitoring systems may already be configured for direct notification of many types of critical security alerts.
  "
  desc  'rationale', ''
  desc  'check', "
    Login to VMware Aria Operations for Logs as an administrator.

    In the slide-out menu on the left, choose Management >> Hosts.

    If the \"Inactive hosts notification\" is not enabled, this is a finding.
  "
  desc 'fix', "
    Login to VMware Aria Operations for Logs as an administrator.

    In the slide-out menu on the left, choose Management >> Hosts.

    Click the checkbox next to \"Inactive hosts notification\" and configure an alerting threshold for notifications according to organizational policies.
  "
  impact 0.3
  tag severity: 'low'
  tag gtitle: 'SRG-APP-000360-AU-000130'
  tag satisfies: ['SRG-APP-000361-AU-000140']
  tag gid: 'V-VLIA-8X-000009'
  tag rid: 'SV-VLIA-8X-000009'
  tag stig_id: 'VLIA-8X-000009'
  tag cci: %w(CCI-001858 CCI-001861)
  tag nist: ['AU-5 (2)', 'AU-5 (4)']

  describe 'Inactive Host Notification configuration is a manual check' do
    skip 'Ensuring Inactive Host Notification is enabled is a manual check.'
  end
end
