control 'VCSA-70-000070' do
  title 'The vCenter Server must prohibit password reuse for a minimum of five generations.'
  desc  "
    Password complexity, or strength, is a measure of the effectiveness of a password in resisting attempts at guessing and brute-force attacks.

    To meet password policy requirements, passwords must be changed at specific policy-based intervals.

    If the information system or application allows the user to consecutively reuse their password when that password has exceeded its defined lifetime, the result is a password that is not changed per policy requirements.
  "
  desc  'rationale', ''
  desc  'check', "
    From the vSphere Client, go to Administration >> Single Sign On >> Configuration >> Local Accounts >> Password Policy.

    View the value of the \"Restrict reuse\" setting.

    If the \"Restrict reuse\" policy is not set to \"5\" or more, this is a finding.
  "
  desc 'fix', "
    From the vSphere Client, go to Administration >> Single Sign On >> Configuration >> Local Accounts >> Password Policy.

    Click \"Edit\", enter \"5\" as the \"Restrict reuse\" setting, and click \"OK\".
  "
  impact 0.5
  tag severity: 'medium'
  tag gtitle: 'SRG-APP-000165'
  tag gid: 'V-256326'
  tag rid: 'SV-256326r885589_rule'
  tag stig_id: 'VCSA-70-000070'
  tag cci: ['CCI-000200']
  tag nist: ['IA-5 (1) (e)']

  command = '(Get-SsoPasswordPolicy).ProhibitedPreviousPasswordsCount'
  describe powercli_command(command) do
    its('stdout.strip') { should cmp >= 5 }
  end
end
