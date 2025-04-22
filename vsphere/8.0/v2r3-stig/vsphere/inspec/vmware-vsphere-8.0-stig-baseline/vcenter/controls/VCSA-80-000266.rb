control 'VCSA-80-000266' do
  title 'The vCenter Server must require an administrator to unlock an account locked due to excessive login failures.'
  desc 'By requiring that Single Sign-On (SSO) accounts be unlocked manually, the risk of unauthorized access via user password guessing, otherwise known as brute forcing, is reduced. When the account unlock time is set to zero, a locked account can only be unlocked manually by an administrator.'
  desc 'check', 'From the vSphere Client, go to Administration >> Single Sign On >> Configuration >> Local Accounts >> Lockout Policy.

View the value of the "Unlock time" setting.

Unlock time: 0 seconds

If the lockout policy is not configured with "Unlock time" policy of "0", this is a finding.'
  desc 'fix', 'From the vSphere Client, go to Administration >> Single Sign On >> Configuration >> Local Accounts >> Lockout Policy.

Click "Edit".

Set the "Unlock time" to "0" and click "Save".'
  impact 0.5
  tag check_id: 'C-62673r934455_chk'
  tag severity: 'medium'
  tag gid: 'V-258933'
  tag rid: 'SV-258933r961368_rule'
  tag stig_id: 'VCSA-80-000266'
  tag gtitle: 'SRG-APP-000345'
  tag fix_id: 'F-62582r934456_fix'
  tag cci: ['CCI-002238']
  tag nist: ['AC-7 b']

  command = '(Get-SsoLockoutPolicy).AutoUnlockIntervalSec'
  describe powercli_command(command) do
    its('stdout.strip') { should cmp '0' }
  end
end
