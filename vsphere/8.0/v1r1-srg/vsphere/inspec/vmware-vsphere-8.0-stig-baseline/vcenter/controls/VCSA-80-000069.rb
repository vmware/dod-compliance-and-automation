control 'VCSA-80-000069' do
  title 'The vCenter Server passwords must be at least 15 characters in length.'
  desc  "
    The shorter the password, the lower the number of possible combinations that need to be tested before the password is compromised.

    Password complexity, or strength, is a measure of the effectiveness of a password in resisting attempts at guessing and brute-force attacks. Password length is one factor of several that helps to determine strength and how long it takes to crack a password. The shorter the password, the lower the number of possible combinations that need to be tested before the password is compromised.

    Use of more characters in a password helps to exponentially increase the time and/or resources required to compromise the password.
  "
  desc  'rationale', ''
  desc  'check', "
    From the vSphere Client, go to Administration >> Single Sign On >> Configuration >> Local Accounts >> Password Policy.

    View the value of the \"Minimum Length\" setting.

    Minimum Length: 15

    If the password policy is not configured with a \"Minimum Length\" policy of \"15\" or more, this is a finding.
  "
  desc 'fix', "
    From the vSphere Client, go to Administration >> Single Sign On >> Configuration >> Local Accounts >> Password Policy.

    Click \"Edit\".

    Set the \"Minimum Length\" to \"15\" and click \"Save\".
  "
  impact 0.5
  tag severity: 'medium'
  tag gtitle: 'SRG-APP-000164'
  tag gid: 'V-VCSA-80-000069'
  tag rid: 'SV-VCSA-80-000069'
  tag stig_id: 'VCSA-80-000069'
  tag cci: ['CCI-000205']
  tag nist: ['IA-5 (1) (a)']

  command = '(Get-SsoPasswordPolicy).MinLength'
  describe powercli_command(command) do
    its('stdout.strip') { should cmp >= 15 }
  end
end
