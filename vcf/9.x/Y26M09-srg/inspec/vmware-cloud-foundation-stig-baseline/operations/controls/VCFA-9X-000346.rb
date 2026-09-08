control 'VCFA-9X-000346' do
  title 'VMware Cloud Foundation Operations must enforce password complexity requirements.'
  desc  "
    Use of a complex password helps to increase the time and resources required to compromise the password. Password complexity, or strength, is a measure of the effectiveness of a password in resisting attempts at guessing and brute-force attacks.

    Password complexity is one factor of several that determine how long it takes to crack a password. The more complex the password is, the greater the number of possible combinations that need to be tested before the password is compromised.
  "
  desc  'rationale', ''
  desc  'check', "
    From VCF Operations, go to Administration >> Global Settings >> User Access >> Password Policy.

    Review the Policy Definition section.

    If the password policy definition is not configured with a minimum length of 15 or more characters, this is a finding.

    If the password policy definition is not configured to require at least 1 uppercase character, this is a finding.

    If the password policy definition is not configured to require at least 1 lowercase character, this is a finding.

    If the password policy definition is not configured to require at least 1 numeric character, this is a finding.

    If the password policy definition is not configured to require at least 1 special character, this is a finding.

    If the Password Policy is not activated, this is a finding.
  "
  desc 'fix', "
    From VCF Operations, go to Administration >> Global Settings >> User Access >> Password Policy.

    If the Password Policy is not activated, click on the \"Deactivated\" radio button to enable it and click \"Save\".

    Once activated configure the following settings for the Policy Definition:

    Configure the \"Minimum password length\" to 15 or more.

    Configure the \"Character Requirements\" to require at least \"1\" uppercase character.

    Configure the \"Character Requirements\" to require at least \"1\" lowercase character.

    Configure the \"Character Requirements\" to require at least \"1\" numeric character.

    Configure the \"Character Requirements\" to require at least \"1\" special character.

    Click \"Save\".
  "
  impact 0.5
  tag severity: 'medium'
  tag gtitle: 'SRG-APP-000164'
  tag gid: 'V-VCFA-9X-000346'
  tag rid: 'SV-VCFA-9X-000346'
  tag stig_id: 'VCFA-9X-000346'
  tag cci: ['CCI-004066']
  tag nist: ['IA-5 (1) (h)']

  describe 'This check is either manual due to no available API or is policy based and must be reviewed manually.' do
    skip 'This check is either manual due to no available API or is policy based and must be reviewed manually.'
  end
end
