control 'VCFA-9X-000357' do
  title 'VMware Cloud Foundation Operations for Logs must enforce password complexity requirements.'
  desc  "
    Use of a complex password helps to increase the time and resources required to compromise the password. Password complexity, or strength, is a measure of the effectiveness of a password in resisting attempts at guessing and brute-force attacks.

    Password complexity is one factor of several that determine how long it takes to crack a password. The more complex the password is, the greater the number of possible combinations that need to be tested before the password is compromised.
  "
  desc  'rationale', ''
  desc  'check', "
    If VCF Operations for Logs is not deployed, this is not applicable.

    From VCF Operations for Logs, go to Configuration >> General.

    Review the \"Password Policy Restriction\" configuration.

    If \"Password Policy Restriction\" is disabled, this is a finding.
  "
  desc 'fix', "
    From VCF Operations for Logs, go to Configuration >> General.

    Under \"Security Technical Implementation Guide\" click the radio button next to \"Password Policy Restriction\" to enable it and click Save.
  "
  impact 0.5
  tag severity: 'medium'
  tag gtitle: 'SRG-APP-000164'
  tag gid: 'V-VCFA-9X-000357'
  tag rid: 'SV-VCFA-9X-000357'
  tag stig_id: 'VCFA-9X-000357'
  tag cci: ['CCI-004066']
  tag nist: ['IA-5 (1) (h)']

  if input('opslogs_deployed')
    describe 'This check is either manual due to no available API or is policy based and must be reviewed manually.' do
      skip 'This check is either manual due to no available API or is policy based and must be reviewed manually.'
    end
  else
    impact 0.0
    describe 'VCF Operations for Logs is not deployed in the target environment. This control is N/A.' do
      skip 'VCF Operations for Logs is not deployed in the target environment. This control is N/A.'
    end
  end
end
