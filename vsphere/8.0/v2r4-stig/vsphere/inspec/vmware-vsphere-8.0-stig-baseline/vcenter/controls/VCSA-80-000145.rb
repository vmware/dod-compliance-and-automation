control 'VCSA-80-000145' do
  title 'The vCenter Server must set the interval for counting failed login attempts to at least 15 minutes.'
  desc 'By limiting the number of failed login attempts, the risk of unauthorized system access via user password guessing, otherwise known as brute forcing, is reduced. Limits are imposed by locking the account.'
  desc 'check', 'From the vSphere Client, go to Administration >> Single Sign On >> Configuration >> Local Accounts >> Lockout Policy.

View the value of the "Time interval between failures" setting.

Time interval between failures: 900 seconds

If the lockout policy is not configured with "Time interval between failures" policy of "900" or more, this is a finding.'
  desc 'fix', 'From the vSphere Client, go to Administration >> Single Sign On >> Configuration >> Local Accounts >> Lockout Policy.

Click "Edit".

Set the "Time interval between failures" to "900" and click "Save".'
  impact 0.5
  tag check_id: 'C-62664r934428_chk'
  tag severity: 'medium'
  tag gid: 'V-258924'
  tag rid: 'SV-258924r961368_rule'
  tag stig_id: 'VCSA-80-000145'
  tag gtitle: 'SRG-APP-000345'
  tag fix_id: 'F-62573r934429_fix'
  tag cci: ['CCI-002238']
  tag nist: ['AC-7 b']

  command = '(Get-SsoLockoutPolicy).FailedAttemptIntervalSec'
  describe powercli_command(command) do
    its('stdout.strip') { should cmp >= 900 }
  end
end
