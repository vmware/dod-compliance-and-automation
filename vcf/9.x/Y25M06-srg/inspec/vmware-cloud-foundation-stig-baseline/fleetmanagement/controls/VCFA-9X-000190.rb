control 'VCFA-9X-000190' do
  title 'VMware Cloud Foundation must only allow the use of DOD PKI established certificate authorities for verification of the establishment of protected sessions.'
  desc  "
    Untrusted Certificate Authorities (CA) can issue certificates, but they may be issued by organizations or individuals that seek to compromise DOD systems or by organizations with insufficient security controls. If the CA used for verifying the certificate is not a DOD-approved CA, trust of this CA has not been established.

    The DOD will only accept PKI certificates obtained from a DOD-approved internal or external certificate authority. Reliance on CAs for the establishment of secure sessions includes, for example, the use of TLS certificates.
  "
  desc  'rationale', ''
  desc  'check', "
    Centralized certificate management for VCF component TLS certificates is provided via the VCF Admin Console.

    From VCF Operations, go to Fleet Management >> Certificates.

    Review each VCF instance and VCF management component's certificate and its issuer.

    If VCF components are not configured with a TLS certificate from a DOD-approved CA, this is a finding.
  "
  desc  'fix', "
    For complete details on configuring certificates in VCF, refer to the product documentation.

    To generate a CSR and obtain a new TLS certificate from an external CA, do the following:

    From VCF Operations, go to Fleet Management >> Certificates.

    Locate the target component and select it from the list.

    Generate a CSR for the component by clicking the ellipse (...) and selecting \"Generate CSR\". Fill out the CSR and click Save.

    Once generated the CSR can be downloaded clicking the ellipse (...) and selecting \"Download CSRs\". Select the target CSR and click Download.

    Obtain a new certificate using the CSR from your external CA prior to the next steps.

    To replace a VCF component's TLS certificate with a certificate issued from an external CA, do the following:

    From VCF Operations, go to Fleet Management >> Certificates.

    Import the new certificate by clicking the ellipse (...) and selecting \"Import Certificate\". Provide a name and paste the contents of the new certificate or provide the file directly. Click Validate to validate the certificate then click Save.

    Locate the target component and select it from the list.

    Click \"Replace with Imported Certificate\". In the \"Select imported certificate\" dropdown locate the imported certificate and click Replace.

    Repeat the previous steps as necessary for all VCF components.
  "
  impact 0.5
  tag severity: 'medium'
  tag gtitle: 'SRG-APP-000427'
  tag gid: 'V-VCFA-9X-000190'
  tag rid: 'SV-VCFA-9X-000190'
  tag stig_id: 'VCFA-9X-000190'
  tag cci: ['CCI-002470']
  tag nist: ['SC-23 (5)']

  describe 'This check is either manual due to no available API or is policy based and must be reviewed manually.' do
    skip 'This check is either manual due to no available API or is policy based and must be reviewed manually.'
  end
end
