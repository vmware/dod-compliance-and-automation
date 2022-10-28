control 'VCSA-70-000073' do
  title 'The vCenter Server passwords must contain at least one numeric character.'
  desc  "
    Use of a complex password helps to increase the time and resources required to compromise the password. Password complexity, or strength, is a measure of the effectiveness of a password in resisting attempts at guessing and brute-force attacks.

    Password complexity is one factor of several that determine how long it takes to crack a password. The more complex the password, the greater the number of possible combinations that need to be tested before the password is compromised.
  "
  desc  'rationale', ''
  desc  'check', "
    From the vSphere Client, go to Administration >> Single Sign On >> Configuration >> Local Accounts >> Password Policy.

    The following password requirement should be set with at least the stated value:

    Numeric Characters: At least 1

    If this password complexity policy is not configured as stated, this is a finding.
  "
  desc 'fix', "
    From the vSphere Client, go to Administration >> Single Sign On >> Configuration >> Local Accounts >> Password Policy.

    Click \"Edit\".

    Set Numeric Characters to at least \"1\" and click \"Save\".
  "
  impact 0.5
  tag severity: 'medium'
  tag gtitle: 'SRG-APP-000168'
  tag gid: nil
  tag rid: nil
  tag stig_id: 'VCSA-70-000073'
  tag cci: ['CCI-000194']
  tag nist: ['IA-5 (1) (a)']

  command = '(Get-SsoPasswordPolicy).MinNumericCount'
  describe powercli_command(command) do
    its('stdout.strip') { should cmp '1' }
  end
end
