control 'VCFA-9X-000384' do
  title 'VMware Cloud Foundation Operations HCX must only allow the use of DOD PKI established certificate authorities for verification of the establishment of protected sessions.'
  desc  "
    Untrusted Certificate Authorities (CA) can issue certificates, but they may be issued by organizations or individuals that seek to compromise DOD systems or by organizations with insufficient security controls. If the CA used for verifying the certificate is not a DOD-approved CA, trust of this CA has not been established.

    The DOD will only accept PKI certificates obtained from a DOD-approved internal or external certificate authority. Reliance on CAs for the establishment of secure sessions includes, for example, the use of TLS certificates.
  "
  desc  'rationale', ''
  desc  'check', "
    If VCF Operations HCX is not deployed, this is not applicable.

    Review the configured certificate for VCF Operations HCX by browsing to the VCF Operations HCX Administration interface and examining the presented certificate.

    If VCF Operations HCX is not configured with a TLS certificate from a DOD-approved CA, this is a finding.
  "
  desc  'fix', "
    For complete details on configuring certificates in VCF Operations HCX, refer to the product documentation.

    The following steps presume a new certificate has been requested and is available for use.

    From the VCF Operations HCX Administration interface, go to Administration >> Certificate >> Server Certificate.

    Enter the new certificate details in the \"Server Certificate\" and \"Private Key\" fields and click \"Apply\".
  "
  impact 0.5
  tag severity: 'medium'
  tag gtitle: 'SRG-APP-000427'
  tag gid: 'V-VCFA-9X-000384'
  tag rid: 'SV-VCFA-9X-000384'
  tag stig_id: 'VCFA-9X-000384'
  tag cci: ['CCI-002470']
  tag nist: ['SC-23 (5)']

  if input('opshcx_deployed')
    describe 'This check is manual due to no available API or policy based and must be reviewed manually.' do
      skip 'This check is manual due to no available API or policy based and must be reviewed manually.'
    end
  else
    impact 0.0
    describe 'VCF Operations HCX is not deployed in the target environment. This control is N/A.' do
      skip 'VCF Operations HCX is not deployed in the target environment. This control is N/A.'
    end
  end
end
