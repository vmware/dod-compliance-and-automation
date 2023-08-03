control 'VCSA-70-000069' do
  title 'The vCenter Server passwords must be at least 15 characters in length.'
  desc 'The shorter the password, the lower the number of possible combinations that need to be tested before the password is compromised.

Password complexity, or strength, is a measure of the effectiveness of a password in resisting attempts at guessing and brute-force attacks. Password length is one factor of several that helps to determine strength and how long it takes to crack a password.

Use of more characters in a password helps to exponentially increase the time and/or resources required to compromise the password.'
  desc 'check', 'From the vSphere Client, go to Administration >> Single Sign On >> Configuration >> Local Accounts >> Password Policy.

The following password requirement should be set with at least the stated value:

Minimum Length: 15

If this password policy is not configured as stated, this is a finding.'
  desc 'fix', 'From the vSphere Client, go to Administration >> Single Sign On >> Configuration >> Local Accounts >> Password Policy.

Click "Edit".

Set the "Minimum Length" to "15" and click "Save".'
  impact 0.5
  tag check_id: 'C-60000r885584_chk'
  tag severity: 'medium'
  tag gid: 'V-256325'
  tag rid: 'SV-256325r885586_rule'
  tag stig_id: 'VCSA-70-000069'
  tag gtitle: 'SRG-APP-000164'
  tag fix_id: 'F-59943r885585_fix'
  tag cci: ['CCI-000205']
  tag nist: ['IA-5 (1) (a)']

  command = '(Get-SsoPasswordPolicy).MinLength'
  describe powercli_command(command) do
    its('stdout.strip') { should cmp '15' }
  end
end
