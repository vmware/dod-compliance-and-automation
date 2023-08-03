control 'VCSA-70-000266' do
  title 'The vCenter Server must require an administrator to unlock an account locked due to excessive login failures.'
  desc 'By requiring that Single Sign-On (SSO) accounts be unlocked manually, the risk of unauthorized access via user password guessing, otherwise known as brute forcing, is reduced. When the account unlock time is set to zero, once an account is locked it can only be unlocked manually by an administrator.'
  desc 'check', 'From the vSphere Client, go to Administration >> Single Sign On >> Configuration >> Local Accounts >> Lockout Policy.

Verify the following lockout policy is set as follows:

Unlock time: 0

If this account lockout policy is not configured as stated, this is a finding.'
  desc 'fix', 'From the vSphere Client, go to Administration >> Single Sign On >> Configuration >> Local Accounts >> Lockout Policy.

Click "Edit".

Set the "Unlock time" to "0" and click "Save".'
  impact 0.5
  tag check_id: 'C-60021r885647_chk'
  tag severity: 'medium'
  tag gid: 'V-256346'
  tag rid: 'SV-256346r885649_rule'
  tag stig_id: 'VCSA-70-000266'
  tag gtitle: 'SRG-APP-000345'
  tag fix_id: 'F-59964r885648_fix'
  tag cci: ['CCI-002238']
  tag nist: ['AC-7 b']

  command = '(Get-SsoLockoutPolicy).AutoUnlockIntervalSec'
  describe powercli_command(command) do
    its('stdout.strip') { should cmp '0' }
  end
end
