control 'VCFA-9X-000377' do
  title 'VMware Cloud Foundation Operations for Networks must disable automatic certificate validation for data sources.'
  desc  "
    A certificate's certification path is the path from the end entity certificate to a trusted root certification authority (CA). Certification path validation is necessary for a relying party to make an informed decision regarding acceptance of an end entity certificate.

    Certification path validation includes checks such as certificate issuer trust, time validity, and revocation status for each certificate in the certification path. Revocation status information for CA and subject certificates in a certification path is commonly provided via certificate revocation lists (CRLs) or online certificate status protocol (OCSP) responses.
  "
  desc  'rationale', ''
  desc  'check', "
    If VCF Operations for Networks is not deployed, this is not applicable.

    From VCF Operations for Networks, go to Settings >> System Configuration.

    Review the value of the \"Security Certificate Validation\" setting.

    If \"Security Certificate Validation\" is not set to manual acceptance, this is a finding.
  "
  desc 'fix', "
    From VCF Operations for Networks, go to Settings >> System Configuration.

    Click \"Edit\" next to \"Security Certificate Validation\" setting.

    Select \"Manual Acceptance\" from the drop down menu and click \"Save\".
  "
  impact 0.5
  tag severity: 'medium'
  tag gtitle: 'SRG-APP-000605'
  tag gid: 'V-VCFA-9X-000377'
  tag rid: 'SV-VCFA-9X-000377'
  tag stig_id: 'VCFA-9X-000377'
  tag cci: ['CCI-000185']
  tag nist: ['IA-5 (2) (b) (1)']

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
