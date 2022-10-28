control 'VCSA-70-000023' do
  title 'The vCenter Server must enforce the limit of three consecutive invalid logon attempts by a user.'
  desc  'By limiting the number of failed login attempts, the risk of unauthorized system access via user password guessing, otherwise known as brute forcing, is reduced. Limits are imposed by locking the account. '
  desc  'rationale', ''
  desc  'check', "
    From the vSphere Client, go to Administration >> Single Sign On >> Configuration >> Local Accounts >> Lockout Policy.

    The following lockout policy should be set at follows:

    Maximum number of failed login attempts: 3

    If this account lockout policy is not configured as stated, this is a finding.
  "
  desc 'fix', "
    From the vSphere Client, go to Administration >> Single Sign On >> Configuration >> Local Accounts >> Lockout Policy.

    Click \"Edit\".

    Set the Maximum number of failed login attempts to \"3\" and click \"Save\".
  "
  impact 0.5
  tag severity: 'medium'
  tag gtitle: 'SRG-APP-000065'
  tag gid: nil
  tag rid: nil
  tag stig_id: 'VCSA-70-000023'
  tag cci: ['CCI-000044']
  tag nist: ['AC-7 a']

  command = '(Get-SsoLockoutPolicy).MaxFailedAttempts'
  describe powercli_command(command) do
    its('stdout.strip') { should cmp '3' }
  end
end
