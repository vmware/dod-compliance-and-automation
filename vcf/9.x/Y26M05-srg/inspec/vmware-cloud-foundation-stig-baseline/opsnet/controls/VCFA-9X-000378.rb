control 'VCFA-9X-000378' do
  title 'VMware Cloud Foundation Operations for Networks must enable FIPS-validated cryptography for external connections.'
  desc  'Without confidentiality protection mechanisms, unauthorized individuals may gain access to sensitive information via a remote access session. '
  desc  'rationale', ''
  desc  'check', "
    If VCF Operations for Networks is not deployed, this is not applicable.

    From VCF Operations for Networks, go to Settings >> System Configuration.

    Review the value of the \"FIPS Mode For External Connections\" setting.

    If \"FIPS Mode For External Connections\" is not enabled, this is a finding.
  "
  desc 'fix', "
    From VCF Operations for Networks, go to Settings >> System Configuration.

    Click the radio button next to \"FIPS Mode For External Connections\" and click \"Confirm\".
  "
  impact 0.5
  tag severity: 'medium'
  tag gtitle: 'SRG-APP-000555'
  tag gid: 'V-VCFA-9X-000378'
  tag rid: 'SV-VCFA-9X-000378'
  tag stig_id: 'VCFA-9X-000378'
  tag cci: ['CCI-002450']
  tag nist: ['SC-13 b']

  if input('opsnet_deployed')
    describe 'This check is either manual due to no available API or is policy based and must be reviewed manually.' do
      skip 'This check is either manual due to no available API or is policy based and must be reviewed manually.'
    end
  else
    impact 0.0
    describe 'VCF Operations for Networks is not deployed in the target environment. This control is N/A.' do
      skip 'VCF Operations for Networks is not deployed in the target environment. This control is N/A.'
    end
  end
end
