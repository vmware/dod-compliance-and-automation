control 'WOAA-3X-000042' do
  title 'Workspace ONE Access must be configured to not accept certificates that have been revoked for PKI-based authentication.'
  desc  "
    Without path validation, an informed trust decision by the relying party cannot be made when presented with any certificate not already explicitly trusted.

    A trust anchor is an authoritative entity represented via a public key and associated data. It is used in the context of public key infrastructures, X.509 digital certificates, and DNSSEC.

    When there is a chain of trust, usually the top entity to be trusted becomes the trust anchor; it can be, for example, a Certification Authority (CA). A certification path starts with the subject certificate and proceeds through a number of intermediate certificates up to a trusted root certificate, typically issued by a trusted CA.

    This requirement verifies that a certification path to an accepted trust anchor is used to for certificate validation and that the path includes status information. Path validation is necessary for a relying party to make an informed trust decision when presented with any certificate not already explicitly trusted. Status information for certification paths includes certificate revocation lists or online certificate status protocol responses.
  "
  desc  'rationale', ''
  desc  'check', "
    Login to the Workspace ONE Access admin console at \"https://<hostname>/SAAS/admin\" using administrative credentials.

    On the VMware Identity Manager console Identity & Access Management tab, select Setup.

    On the Connectors page, select the Worker link for the connector being checked.

    Click Auth Adapters and then Certificate Adapter.

    If neither \"Cert Revocation\" or \"OCSP Revocation\" are enabled, this is a finding.
  "
  desc 'fix', "
    Login to the Workspace ONE Access admin console at \"https://<hostname>/SAAS/admin\" using administrative credentials.

    On the VMware Identity Manager console Identity & Access Management tab, select Setup.

    On the Connectors page, select the Worker link for the connector being checked.

    Click Auth Adapters and then Certificate Adapter.

    To enable CRL Revocation checking:

    Check the \"Enable Cert Revocation\" box and configure the CRL settings as required then click Save.

    To enable OCSP Revocation checking:

    Check the \"Enable OCSP Revocation\" box and configure the OCSP URL and other settings as required then click Save.
  "
  impact 0.7
  tag severity: 'high'
  tag gtitle: 'SRG-APP-000175-AAA-000580'
  tag gid: 'V-WOAA-3X-000042'
  tag rid: 'SV-WOAA-3X-000042'
  tag stig_id: 'WOAA-3X-000042'
  tag cci: ['CCI-000185']
  tag nist: ['IA-5 (2) (a)']

  describe 'This control is a manual audit...skipping...' do
    skip 'This control is a manual audit...skipping...'
  end
end
