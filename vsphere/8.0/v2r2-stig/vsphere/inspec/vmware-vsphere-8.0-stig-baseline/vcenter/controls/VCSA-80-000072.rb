control 'VCSA-80-000072' do
  title 'The vCenter Server passwords must contain at least one lowercase character.'
  desc 'Use of a complex password helps to increase the time and resources required to compromise the password. Password complexity, or strength, is a measure of the effectiveness of a password in resisting attempts at guessing and brute-force attacks.

Password complexity is one factor of several that determine how long it takes to crack a password. The more complex the password, the greater the number of possible combinations that need to be tested before the password is compromised.'
  desc 'check', 'From the vSphere Client, go to Administration >> Single Sign On >> Configuration >> Local Accounts >> Password Policy.

View the value of the "Character requirements" setting.

Character requirements: At least 1 lowercase characters

If the password policy is not configured with "Character requirements" policy requiring "1" or more lowercase characters, this is a finding.'
  desc 'fix', 'From the vSphere Client, go to Administration >> Single Sign On >> Configuration >> Local Accounts >> Password Policy.

Click "Edit".

Set "lowercase characters" to at least "1" and click "Save".'
  impact 0.5
  tag check_id: 'C-62654r934398_chk'
  tag severity: 'medium'
  tag gid: 'V-258914'
  tag rid: 'SV-258914r1003594_rule'
  tag stig_id: 'VCSA-80-000072'
  tag gtitle: 'SRG-APP-000167'
  tag fix_id: 'F-62563r934399_fix'
  tag cci: ['CCI-004066']
  tag nist: ['IA-5 (1) (h)']

  command = '(Get-SsoPasswordPolicy).MinLowercaseCount'
  describe powercli_command(command) do
    its('stdout.strip') { should cmp >= 1 }
  end
end
