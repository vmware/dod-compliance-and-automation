control 'VCFA-9X-000346' do
  title 'VMware Cloud Foundation Operations must enforce password complexity requirements.'
  desc  "
    Use of a complex password helps to increase the time and resources required to compromise the password. Password complexity, or strength, is a measure of the effectiveness of a password in resisting attempts at guessing and brute-force attacks.

    Password complexity is one factor of several that determine how long it takes to crack a password. The more complex the password is, the greater the number of possible combinations that need to be tested before the password is compromised.
  "
  desc  'rationale', ''
  desc  'check', "
    From VCF Operations, go to Administration >> Global Settings >> User Access >> Password Policy.

    Review the password strength section.

    If the password strength policy is not configured with a minimum length of 15 or more, this is a finding.

    If the password strength policy is not configured to enable \"Passwords must contain numbers\", this is a finding.

    If the password strength policy is not configured to enable \"Passwords must not match user names\", this is a finding.

    If the password strength policy is not configured to enable \"Passwords must contain at least one uppercase and one lowercase letter\", this is a finding.

    If the password strength policy is not configured to enable \"Passwords must contain special characters\", this is a finding.

    If the password strength policy is not activated, this is a finding.
  "
  desc 'fix', "
    From VCF Operations, go to Administration >> Global Settings >> User Access >> Password Policy >> Password Strength.

    If the password strength policy is not activated, click on the \"Deactivated\" radio button to enable it and click \"Save\".

    Once activated configure the following policies:

    Configure the \"Minimum password length\" to 15 or more.

    Enable the \"Passwords must contain numbers\" policy.

    Enable the \"Passwords must not match user names\" policy.

    Enable the \"Passwords must contain at least one uppercase and one lowercase letter\" policy.

    Enable the \"Passwords must contain special characters\" policy.

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
