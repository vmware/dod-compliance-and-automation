control 'VCSA-70-000071' do
  title 'The vCenter Server passwords must contain at least one uppercase character.'
  desc 'Use of a complex password helps to increase the time and resources required to compromise the password. Password complexity, or strength, is a measure of the effectiveness of a password in resisting attempts at guessing and brute-force attacks.

Password complexity is one factor of several that determine how long it takes to crack a password. The more complex the password is, the greater the number of possible combinations that need to be tested before the password is compromised.'
  desc 'check', 'From the vSphere Client, go to Administration >> Single Sign On >> Configuration >> Local Accounts >> Password Policy.

Set the following password requirement with at least the stated value:

Upper-case Characters: At least 1

If this password complexity policy is not configured as stated, this is a finding.'
  desc 'fix', 'From the vSphere Client, go to Administration >> Single Sign On >> Configuration >> Local Accounts >> Password Policy.

Click "Edit".

Set "Upper-case Characters" to at least "1" and click "Save".'
  impact 0.5
  tag check_id: 'C-60002r885590_chk'
  tag severity: 'medium'
  tag gid: 'V-256327'
  tag rid: 'SV-256327r885592_rule'
  tag stig_id: 'VCSA-70-000071'
  tag gtitle: 'SRG-APP-000166'
  tag fix_id: 'F-59945r885591_fix'
  tag cci: ['CCI-000192']
  tag nist: ['IA-5 (1) (a)']

  command = '(Get-SsoPasswordPolicy).MinUppercaseCount'
  describe powercli_command(command) do
    its('stdout.strip') { should cmp '1' }
  end
end
