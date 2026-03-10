control 'VCFA-9X-000139' do
  title 'The VMware Cloud Foundation vCenter Server must automatically lock the account until the locked account is released by an administrator when three unsuccessful login attempts in 15 minutes are exceeded.'
  desc  'By limiting the number of failed login attempts, the risk of unauthorized system access via user password guessing, otherwise known as brute forcing, is reduced. Limits are imposed by locking the account.'
  desc  'rationale', ''
  desc  'check', "
    From the vSphere Client, go to Administration >> Single Sign On >> Configuration >> Local Accounts >> Lockout Policy.

    View the value of the \"Unlock time\" setting.

    Unlock time: 0 seconds

    If the lockout policy is not configured with \"Unlock time\" policy of \"0\", this is a finding.
  "
  desc 'fix', "
    From the vSphere Client, go to Administration >> Single Sign On >> Configuration >> Local Accounts >> Lockout Policy.

    Click \"Edit\".

    Set the \"Unlock time\" to \"0\" and click \"Save\".
  "
  impact 0.5
  tag severity: 'medium'
  tag gtitle: 'SRG-APP-000345'
  tag gid: 'V-VCFA-9X-000139'
  tag rid: 'SV-VCFA-9X-000139'
  tag stig_id: 'VCFA-9X-000139'
  tag cci: ['CCI-002238']
  tag nist: ['AC-7 b']

  command = 'Get-SsoLockoutPolicy | ConvertTo-Json -Depth 2 -WarningAction SilentlyContinue'
  result = powercli_command(command).stdout.strip

  if result.blank?
    describe "No results returned from command: #{command} . Troubleshoot issue and rerun scan." do
      skip "No results returned from command: #{command} . Troubleshoot issue and rerun scan."
    end
  else
    describe 'The vCenter Server SSO lockout policy:' do
      subject { json(content: result) }
      its(['AutoUnlockIntervalSec']) { should cmp 0 }
    end
  end
end
