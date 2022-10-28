control 'VCSA-70-000145' do
  title 'The vCenter Server must set the interval for counting failed login attempts to at least 15 minutes.'
  desc  'By limiting the number of failed login attempts, the risk of unauthorized system access via user password guessing, otherwise known as brute forcing, is reduced. Limits are imposed by locking the account.'
  desc  'rationale', ''
  desc  'check', "
    From the vSphere Client, go to Administration >> Single Sign On >> Configuration >> Local Accounts >> Lockout Policy.

    The following lockout policy should be set at follows:

    Time interval between failures: 900 seconds

    If this lockout policy is not configured as stated, this is a finding.
  "
  desc 'fix', "
    From the vSphere Client, go to Administration >> Single Sign On >> Configuration >> Local Accounts >> Lockout Policy.

    Click \"Edit\".

    Set the Time interval between failures to \"900\" and click \"Save\".
  "
  impact 0.5
  tag severity: 'medium'
  tag gtitle: 'SRG-APP-000345'
  tag gid: nil
  tag rid: nil
  tag stig_id: 'VCSA-70-000145'
  tag cci: ['CCI-002238']
  tag nist: ['AC-7 b']

  command = '(Get-SsoLockoutPolicy).FailedAttemptIntervalSec'
  describe powercli_command(command) do
    its('stdout.strip') { should cmp '900' }
  end
end
