control 'VRPA-8X-000006' do
  title 'vRealize Operations Manager server session timeout must be configured.'
  desc  'If communications sessions remain open for extended periods of time even when unused, there is the potential for an adversary to hijack the session and use it to gain access to the device or networks to which it is attached. Terminating sessions after a logout event or after a certain period of inactivity is a method for mitigating the risk of this vulnerability. When a user management session becomes idle, or when a user logs out of the management interface, the application server must terminate the session.'
  desc  'rationale', ''
  desc  'check', "
    Login to the vRealize Operations Manager portal as an administrator.

    Navigate to Administration >> Global Settings.

    If the \"Session Timeout:\" setting is not “15” minutes or less, this is a finding.
  "
  desc 'fix', "
    Login to the vRealize Operations Manager portal as an administrator.

    Navigate to Administration >> Global Settings.

    Select the Session Timeout line and click the edit icon.  Enter 15 minutes and click Save.
  "
  impact 0.5
  tag severity: 'medium'
  tag gtitle: 'SRG-APP-000220-AS-000148'
  tag gid: 'V-VRPA-8X-000006'
  tag rid: 'SV-VRPA-8X-000006'
  tag stig_id: 'VRPA-8X-000006'
  tag cci: ['CCI-001185']
  tag nist: ['SC-23 (1)']

  describe 'This check is a manual or policy based check' do
    skip 'This must be reviewed manually'
  end
end
