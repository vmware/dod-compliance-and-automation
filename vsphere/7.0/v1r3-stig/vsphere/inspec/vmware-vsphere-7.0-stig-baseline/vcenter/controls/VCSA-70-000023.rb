control 'VCSA-70-000023' do
  title 'The vCenter Server must enforce the limit of three consecutive invalid login attempts by a user.'
  desc 'By limiting the number of failed login attempts, the risk of unauthorized system access via user password guessing, otherwise known as brute forcing, is reduced. Limits are imposed by locking the account.'
  desc 'check', 'From the vSphere Client, go to Administration >> Single Sign On >> Configuration >> Local Accounts >> Lockout Policy.

The lockout policy should be set as follows:

Maximum number of failed login attempts: 3

If this account lockout policy is not configured as stated, this is a finding.'
  desc 'fix', 'From the vSphere Client, go to Administration >> Single Sign On >> Configuration >> Local Accounts >> Lockout Policy.

Click "Edit".

Set the "Maximum number of failed login attempts" to "3" and click "Save".'
  impact 0.5
  tag check_id: 'C-59994r885566_chk'
  tag severity: 'medium'
  tag gid: 'V-256319'
  tag rid: 'SV-256319r885568_rule'
  tag stig_id: 'VCSA-70-000023'
  tag gtitle: 'SRG-APP-000065'
  tag fix_id: 'F-59937r885567_fix'
  tag cci: ['CCI-000044']
  tag nist: ['AC-7 a']

  command = '(Get-SsoLockoutPolicy).MaxFailedAttempts'
  describe powercli_command(command) do
    its('stdout.strip') { should cmp '3' }
  end
end
