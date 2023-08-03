control 'VCSA-70-000074' do
  title 'The vCenter Server passwords must contain at least one special character.'
  desc 'Use of a complex password helps to increase the time and resources required to compromise the password. Password complexity, or strength, is a measure of the effectiveness of a password in resisting attempts at guessing and brute-force attacks.

Password complexity is one factor in determining how long it takes to crack a password. The more complex the password, the greater the number of possible combinations that need to be tested before the password is compromised.

Special characters are not alphanumeric. Examples include: ~ ! @ # $ % ^ *.'
  desc 'check', 'From the vSphere Client, go to Administration >> Single Sign On >> Configuration >> Local Accounts >> Password Policy.

Set the following password requirements with at least the stated value:

Special Characters: At least 1

If this password complexity policy is not configured as stated, this is a finding.'
  desc 'fix', 'From the vSphere Client, go to Administration >> Single Sign On >> Configuration >> Local Accounts >> Password Policy.

Click "Edit".

Set "Special Characters" to at least "1" and click "Save".'
  impact 0.5
  tag check_id: 'C-60005r885599_chk'
  tag severity: 'medium'
  tag gid: 'V-256330'
  tag rid: 'SV-256330r885601_rule'
  tag stig_id: 'VCSA-70-000074'
  tag gtitle: 'SRG-APP-000169'
  tag fix_id: 'F-59948r885600_fix'
  tag cci: ['CCI-001619']
  tag nist: ['IA-5 (1) (a)']

  command = '(Get-SsoPasswordPolicy).MinSpecialCharCount'
  describe powercli_command(command) do
    its('stdout.strip') { should cmp '1' }
  end
end
