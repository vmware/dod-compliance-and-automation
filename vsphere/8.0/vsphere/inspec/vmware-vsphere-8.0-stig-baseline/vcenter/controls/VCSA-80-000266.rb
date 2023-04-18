control 'VCSA-80-000266' do
  title 'The vCenter Server must require an administrator to unlock an account locked due to excessive login failures.'
  desc  'By requiring that Single Sign-On (SSO) accounts be unlocked manually, the risk of unauthorized access via user password guessing, otherwise known as brute forcing, is reduced. When the account unlock time is set to zero, once an account is locked it can only be unlocked manually by an administrator.'
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
  tag gid: 'V-VCSA-80-000266'
  tag rid: 'SV-VCSA-80-000266'
  tag stig_id: 'VCSA-80-000266'
  tag cci: ['CCI-002238']
  tag nist: ['AC-7 b']

  command = '(Get-SsoLockoutPolicy).AutoUnlockIntervalSec'
  describe powercli_command(command) do
    its('stdout.strip') { should cmp '0' }
  end
end
