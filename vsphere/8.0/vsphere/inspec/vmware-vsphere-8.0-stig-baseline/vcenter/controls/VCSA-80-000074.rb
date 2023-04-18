control 'VCSA-80-000074' do
  title 'The vCenter Server passwords must contain at least one special character.'
  desc  "
    Use of a complex password helps to increase the time and resources required to compromise the password. Password complexity, or strength, is a measure of the effectiveness of a password in resisting attempts at guessing and brute-force attacks.

    Password complexity is one factor in determining how long it takes to crack a password. The more complex the password, the greater the number of possible combinations that need to be tested before the password is compromised.

    Special characters are not alphanumeric. Examples include: ~ ! @ # $ % ^ *.
  "
  desc  'rationale', ''
  desc  'check', "
    From the vSphere Client, go to Administration >> Single Sign On >> Configuration >> Local Accounts >> Password Policy.

    View the value of the \"Character requirements\" setting.

    Character requirements: At least 1 special characters

    If the password policy is not configured with \"Character requirements\" policy requiring \"1\" or more special characters, this is a finding.
  "
  desc 'fix', "
    From the vSphere Client, go to Administration >> Single Sign On >> Configuration >> Local Accounts >> Password Policy.

    Click \"Edit\".

    Set \"special characters\" to at least \"1\" and click \"Save\".
  "
  impact 0.5
  tag severity: 'medium'
  tag gtitle: 'SRG-APP-000169'
  tag gid: 'V-VCSA-80-000074'
  tag rid: 'SV-VCSA-80-000074'
  tag stig_id: 'VCSA-80-000074'
  tag cci: ['CCI-001619']
  tag nist: ['IA-5 (1) (a)']

  command = '(Get-SsoPasswordPolicy).MinSpecialCharCount'
  describe powercli_command(command) do
    its('stdout.strip') { should cmp >= 1 }
  end
end
