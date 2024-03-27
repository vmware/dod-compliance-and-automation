control 'VCSA-70-000145' do
  title 'The vCenter Server must set the interval for counting failed login attempts to at least 15 minutes.'
  desc 'By limiting the number of failed login attempts, the risk of unauthorized system access via user password guessing, otherwise known as brute forcing, is reduced. Limits are imposed by locking the account.'
  desc 'check', 'From the vSphere Client, go to Administration >> Single Sign On >> Configuration >> Local Accounts >> Lockout Policy.

Verify the following lockout policy is set as follows:

Time interval between failures: 900 seconds

If this lockout policy is not configured as stated, this is a finding.'
  desc 'fix', 'From the vSphere Client, go to Administration >> Single Sign On >> Configuration >> Local Accounts >> Lockout Policy.

Click "Edit".

Set "Time interval between failures" to "900" and click "Save".'
  impact 0.5
  tag check_id: 'C-60013r885623_chk'
  tag severity: 'medium'
  tag gid: 'V-256338'
  tag rid: 'SV-256338r885625_rule'
  tag stig_id: 'VCSA-70-000145'
  tag gtitle: 'SRG-APP-000345'
  tag fix_id: 'F-59956r885624_fix'
  tag cci: ['CCI-002238']
  tag nist: ['AC-7 b']

  command = '(Get-SsoLockoutPolicy).FailedAttemptIntervalSec'
  describe powercli_command(command) do
    its('stdout.strip') { should cmp '900' }
  end
end
