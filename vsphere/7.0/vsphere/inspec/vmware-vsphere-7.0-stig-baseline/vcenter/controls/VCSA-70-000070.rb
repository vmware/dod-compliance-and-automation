control 'VCSA-70-000070' do
  title 'The vCenter Server must prohibit password reuse for a minimum of five generations.'
  desc  "
    Password complexity, or strength, is a measure of the effectiveness of a password in resisting attempts at guessing and brute-force attacks.

    To meet password policy requirements, passwords need to be changed at specific policy-based intervals.

    If the information system or application allows the user to consecutively reuse their password when that password has exceeded its defined lifetime, the end result is a password that is not changed as per policy requirements.
  "
  desc  'rationale', ''
  desc  'check', "
    From the vSphere Client, go to Administration >> Single Sign On >> Configuration >> Local Accounts >> Password Policy.

    View the value of the \"Restrict reuse\" setting.

    If the \"Restrict reuse\" policy is not set to \"5\" or more, this is a finding.
  "
  desc 'fix', "
    From the vSphere Client, go to Administration >> Single Sign On >> Configuration >> Local Accounts >> Password Policy.

    Click \"Edit\" and enter \"5\" into the \"Restrict reuse\" setting and click \"OK\".
  "
  impact 0.5
  tag severity: 'medium'
  tag gtitle: 'SRG-APP-000165'
  tag gid: nil
  tag rid: nil
  tag stig_id: 'VCSA-70-000070'
  tag cci: ['CCI-000200']
  tag nist: ['IA-5 (1) (e)']

  command = '(Get-SsoPasswordPolicy).ProhibitedPreviousPasswordsCount'
  describe powercli_command(command) do
    its('stdout.strip') { should cmp >= 5 }
  end
end
