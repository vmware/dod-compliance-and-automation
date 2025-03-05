control 'VCSA-80-000150' do
  title 'The vCenter server must provide an immediate real-time alert to the system administrator (SA) and information system security officer (ISSO), at a minimum, of all audit failure events requiring real-time alerts.'
  desc 'It is critical for the appropriate personnel to be aware if a system is at risk of failing to process audit logs as required. Without a real-time alert, security personnel may be unaware of an impending failure of the audit capability and system operation may be adversely affected.

Alerts provide organizations with urgent messages. Real-time alerts provide these messages immediately (i.e., the time from event detection to alert occurs in seconds or less).

'
  desc 'check', 'Review the Central Logging Server being used to verify it is configured to alert the SA and ISSO, at a minimum, on any AO-defined events. Otherwise, this is a finding.

If there are no AO-defined events, this is not a finding.'
  desc 'fix', 'Configure the Central Logging Server being used to alert the SA and ISSO, at a minimum, on any AO-defined events.'
  impact 0.5
  tag check_id: 'C-62666r934434_chk'
  tag severity: 'medium'
  tag gid: 'V-258926'
  tag rid: 'SV-258926r961401_rule'
  tag stig_id: 'VCSA-80-000150'
  tag gtitle: 'SRG-APP-000360'
  tag fix_id: 'F-62575r934435_fix'
  tag satisfies: ['SRG-APP-000360', 'SRG-APP-000379', 'SRG-APP-000510']
  tag cci: ['CCI-000172', 'CCI-001744', 'CCI-001858']
  tag nist: ['AU-12 c', 'CM-3 (5)', 'AU-5 (2)']

  # Setting to impact 0.0 so this does not count as a failure since we cannot validate this anyway.
  impact 0.0
  describe 'This check is a manual or policy based check' do
    skip 'This must be reviewed manually'
  end
end
