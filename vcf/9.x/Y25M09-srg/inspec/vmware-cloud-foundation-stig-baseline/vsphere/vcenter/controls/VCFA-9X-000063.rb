control 'VCFA-9X-000063' do
  title 'The VMware Cloud Foundation vCenter Server must enforce password complexity requirements.'
  desc  "
    Use of a complex password helps to increase the time and resources required to compromise the password. Password complexity, or strength, is a measure of the effectiveness of a password in resisting attempts at guessing and brute-force attacks.

    Password complexity is one factor of several that determine how long it takes to crack a password. The more complex the password is, the greater the number of possible combinations that need to be tested before the password is compromised.
  "
  desc  'rationale', ''
  desc  'check', "
    From the vSphere Client, go to Administration >> Single Sign On >> Configuration >> Local Accounts.

    Review the password policy section.

    If the password policy is not configured with a \"Minimum Length\" policy of 15 or more, this is a finding.

    If the password policy is not configured with a \"Maximum Length\" policy of 20 or more, this is a finding.

    If the password policy is not configured with \"Character requirements\" policy requiring \"1\" or more uppercase characters, this is a finding.

    If the password policy is not configured with \"Character requirements\" policy requiring \"1\" or more lowercase characters, this is a finding.

    If the password policy is not configured with \"Character requirements\" policy requiring \"1\" or more numeric characters, this is a finding.

    If the password policy is not configured with \"Character requirements\" policy requiring \"1\" or more special characters, this is a finding.
  "
  desc 'fix', "
    From the vSphere Client, go to Administration >> Single Sign On >> Configuration >> Local Accounts >> Password Policy.

    Click \"Edit\".

    Configure the \"Minimum Length\" to 15 or more.

    Configure the \"Maximum Length\" to 20 or more.

    Configure the \"Character Requirements\" policy to require at least 1 uppercase, lowercase, numeric, and special characters each.

    Click \"Save\".
  "
  impact 0.5
  tag severity: 'medium'
  tag gtitle: 'SRG-APP-000164'
  tag satisfies: ['SRG-APP-000166', 'SRG-APP-000167', 'SRG-APP-000168', 'SRG-APP-000169', 'SRG-APP-000870']
  tag gid: 'V-VCFA-9X-000063'
  tag rid: 'SV-VCFA-9X-000063'
  tag stig_id: 'VCFA-9X-000063'
  tag cci: ['CCI-004066']
  tag nist: ['IA-5 (1) (h)']

  command = 'Get-SsoPasswordPolicy | ConvertTo-Json -Depth 2 -WarningAction SilentlyContinue'
  result = powercli_command(command).stdout.strip

  if result.blank?
    describe "No results returned from command: #{command} . Troubleshoot issue and rerun scan." do
      skip "No results returned from command: #{command} . Troubleshoot issue and rerun scan."
    end
  else
    describe 'The vCenter Server SSO password policy:' do
      subject { json(content: result) }
      its(['MinLength']) { should cmp >= 15 }
      its(['MaxLength']) { should cmp >= 20 }
      its(['MinUppercaseCount']) { should cmp >= 1 }
      its(['MinLowercaseCount']) { should cmp >= 1 }
      its(['MinNumericCount']) { should cmp >= 1 }
      its(['MinSpecialCharCount']) { should cmp >= 1 }
    end
  end
end
