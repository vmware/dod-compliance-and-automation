control 'UAGA-8X-000153' do
  title 'The UAG must validate certificates used for TLS functions by performing RFC 5280-compliant certification path validation.'
  desc  "
    A certificate's certification path is the path from the end entity certificate to a trusted root certification authority (CA). Certification path validation is necessary for a relying party to make an informed decision regarding acceptance of an end entity certificate.

    Certification path validation includes checks such as certificate issuer trust, time validity and revocation status for each certificate in the certification path. Revocation status information for CA and subject certificates in a certification path is commonly provided via certificate revocation lists (CRLs) or online certificate status protocol (OCSP) responses.

    The UAG provides an \"Extended Server Certificate Validation\" option that will verify information including hostname match, verification status, and validity period.
  "
  desc  'rationale', ''
  desc  'check', "
    Login to the UAG administrative interface as an administrator.

    Select \"Configure Manually\".

    Navigate to Advanced Settings >> System Configuration.

    Click the \"Gear\" icon to check the settings.

    If the \"Extended Server Certificate Validation\" toggle is not enabled, this is a finding.
  "
  desc 'fix', "
    Login to the UAG administrative interface as an administrator.

    Select \"Configure Manually\".

    Navigate to Advanced Settings >> System Configuration.

    Click the \"Gear\" icon to check the settings.

    Scroll to the bottom, and ensure the \"Extended Server Certificate Validation\" toggle is enabled.

    Click \"Save\".
  "
  impact 0.5
  tag severity: 'medium'
  tag gtitle: 'SRG-NET-000164-ALG-000100'
  tag gid: nil
  tag rid: nil
  tag stig_id: 'UAGA-8X-000153'
  tag cci: ['CCI-000185']
  tag nist: ['IA-5 (2) (a)']

  result = uaghelper.runrestcommand('rest/v1/config/settings')

  describe result do
    its('status') { should cmp 200 }
  end

  unless result.status != 200
    jsoncontent = json(content: result.body)
    describe jsoncontent['systemSettings']['extendedServerCertValidationEnabled'] do
      it { should cmp true }
    end
  end
end
