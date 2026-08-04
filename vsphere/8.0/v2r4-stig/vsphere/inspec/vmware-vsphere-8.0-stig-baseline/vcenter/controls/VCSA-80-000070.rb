control 'VCSA-80-000070' do
  title 'The vCenter Server must prohibit password reuse for a minimum of five generations.'
  desc 'Password complexity, or strength, is a measure of the effectiveness of a password in resisting attempts at guessing and brute-force attacks.

To meet password policy requirements, passwords must be changed at specific policy-based intervals.

If the information system or application allows the user to consecutively reuse their password when that password has exceeded its defined lifetime, the result is a password that is not changed per policy requirements.'
  desc 'check', 'From the vSphere Client, go to Administration >> Single Sign On >> Configuration >> Local Accounts >> Password Policy.

View the value of the "Restrict reuse" setting.

Restrict reuse: Users cannot reuse any previous 5 passwords

If the password policy is not configured with a "Restrict reuse" policy of "5" or more, this is a finding.'
  desc 'fix', 'From the vSphere Client, go to Administration >> Single Sign On >> Configuration >> Local Accounts >> Password Policy.

Click "Edit".

Set the "Restrict reuse" to "5" and click "Save".'
  impact 0.5
  tag check_id: 'C-62652r934392_chk'
  tag severity: 'medium'
  tag gid: 'V-258912'
  tag rid: 'SV-258912r1003592_rule'
  tag stig_id: 'VCSA-80-000070'
  tag gtitle: 'SRG-APP-000165'
  tag fix_id: 'F-62561r934393_fix'
  tag cci: ['CCI-004061']
  tag nist: ['IA-5 (1) (b)']

  command = '(Get-SsoPasswordPolicy).ProhibitedPreviousPasswordsCount'
  describe powercli_command(command) do
    its('stdout.strip') { should cmp >= 5 }
  end
end
