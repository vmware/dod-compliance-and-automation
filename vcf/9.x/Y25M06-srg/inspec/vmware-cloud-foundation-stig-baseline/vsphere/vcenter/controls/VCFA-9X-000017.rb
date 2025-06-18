control 'VCFA-9X-000017' do
  title 'The VMware Cloud Foundation vCenter Server must enforce the limit of three consecutive invalid logon attempts by a user during a 15 minute time period.'
  desc  'By limiting the number of failed login attempts, the risk of unauthorized system access via user password guessing, otherwise known as brute forcing, is reduced. Limits are imposed by locking the account. '
  desc  'rationale', ''
  desc  'check', "
    From the vSphere Client, go to Administration >> Single Sign On >> Configuration >> Local Accounts >> Lockout Policy.

    Review the following lockout policies.

    Maximum number of failed login attempts
    Time interval between failures

    If \"Maximum number of failed login attempts\" is not set to 3, this is a finding.

    If \"Time interval between failures\" is not set to 900 seconds or more, this is a finding.
  "
  desc 'fix', "
    From the vSphere Client, go to Administration >> Single Sign On >> Configuration >> Local Accounts >> Lockout Policy.

    Click \"Edit\".

    Set the \"Maximum number of failed login attempts\" to 3 and the \"Time interval between failures\" to 900 seconds then click \"Save\".
  "
  impact 0.5
  tag severity: 'medium'
  tag gtitle: 'SRG-APP-000065'
  tag gid: 'V-VCFA-9X-000017'
  tag rid: 'SV-VCFA-9X-000017'
  tag stig_id: 'VCFA-9X-000017'
  tag cci: ['CCI-000044']
  tag nist: ['AC-7 a']

  command = 'Get-SsoLockoutPolicy | ConvertTo-Json -Depth 2 -WarningAction SilentlyContinue'
  result = powercli_command(command).stdout.strip

  if result.blank?
    describe "No results returned from command: #{command} . Troubleshoot issue and rerun scan." do
      skip "No results returned from command: #{command} . Troubleshoot issue and rerun scan."
    end
  else
    describe 'The vCenter Server SSO lockout policy:' do
      subject { json(content: result) }
      its(['MaxFailedAttempts']) { should cmp 3 }
      its(['FailedAttemptIntervalSec']) { should cmp >= 900 }
    end
  end
end
