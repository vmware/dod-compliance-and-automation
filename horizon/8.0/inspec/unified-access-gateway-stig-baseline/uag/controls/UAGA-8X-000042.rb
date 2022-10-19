control 'UAGA-8X-000042' do
  title 'The UAG must validate certificates used for TLS functions by performing RFC 5280-compliant certification path validation.'
  desc  "
    A certificate's certification path is the path from the end entity certificate to a trusted root certification authority (CA). Certification path validation is necessary for a relying party to make an informed decision regarding acceptance of an end entity certificate.

    Certification path validation includes checks such as certificate issuer trust, time validity and revocation status for each certificate in the certification path. Revocation status information for CA and subject certificates in a certification path is commonly provided via certificate revocation lists (CRLs) or online certificate status protocol (OCSP) responses.
  "
  desc  'rationale', ''
  desc  'check', "
    Login to the UAG administrative interface as an administrator.

    Select \"Configure Manually\".

    Navigate to General Settings >> Authentication.

    Set the toggle to show authentication settings.

    Click the \"Gear\" icon next to \"X.509 Certificate\" to check the settings.

    Ensure the \"Enable X.509 Certificate\" toggle is enabled.

    Ensure the \"Enable Cert Revocation\" toggle is enabled.

    Ensure that at least one of the following options is enabled:

    Option 1:

    > Either the \"Use CRL from Certificates\" checkbox is enabled or the \"CRL Location\" textbox contains a value.

    Option 2:

    > Ensure the \"Enable OCSP Revocation\" checkbox is enabled, and either the \"Use OCSP URL from certificate\" checkbox is enabled or the \"OCSP URL\" textbox contains a value.

    If both options are enabled (CRL and OCSP), ensure the \"Use CRL in case of OCSP Failure\" toggle is enabled.

    If neither CRL nor OCSP certificate validation is enabled, this is a finding.

    Note: When the UAG is installed with FIPS mode enabled, the \"X.509 Certificate\" authentication method is the only one available.
  "
  desc 'fix', "
    Login to the UAG administrative interface as an administrator.

    Select \"Configure Manually\".

    Navigate to General Settings >> Authentication. Set the toggle to show authentication settings.

    Click the \"Gear\" icon next to \"X.509 Certificate\" to edit the settings.

    Ensure the \"Enable X.509 Certificate\" toggle is enabled.

    Ensure the \"Enable Cert Revocation\" toggle is enabled.

    Ensure that at least one of the following options is enabled:

    Option 1:

    > Either the \"Use CRL from Certificates\" checkbox is enabled or the \"CRL Location\" textbox contains a value.

    Option 2:

    > Ensure the \"Enable OCSP Revocation\" checkbox is enabled, and either the \"Use OCSP URL from certificate\" checkbox is enabled or the \"OCSP URL\" textbox contains a value.

    If both options are enabled (CRL and OCSP), ensure the \"Use CRL in case of OCSP Failure\" toggle is enabled.

    Note: When the UAG is installed with FIPS mode enabled, the \"X.509 Certificate\" authentication method is the only one available.
  "
  impact 0.5
  tag severity: 'medium'
  tag gtitle: 'SRG-NET-000164-ALG-000100'
  tag gid: nil
  tag rid: nil
  tag stig_id: 'UAGA-8X-000042'
  tag cci: ['CCI-000185']
  tag nist: ['IA-5 (2) (a)']

  result = uaghelper.runrestcommand('rest/v1/config/authmethod')

  describe result do
    its('status') { should cmp 200 }
  end

  unless result.status != 200
    jsoncontent = json(content: result.body)
    jsoncontent['authMethodSettingsList'].each do |auth|
      next unless auth['displayName'] == 'CertificateAuthAdapter'
      describe 'Validating if Certificate Revocation checking is enabled' do
        subject { auth['enableCertRevocation'] }
        it { should cmp 'true' }
      end

      describe.one do
        describe 'Validating if Certificate CRL checking is enabled' do
          subject { auth['enableCertCRL'] }
          it { should cmp 'true' }
        end
        describe 'Validating if Certificate CRL location has been configured' do
          subject { auth['crlLocation'] }
          it { should_not cmp nil }
        end
        describe 'Validating if Certificate OCSP is enabled' do
          subject { auth['enableOCSP'] }
          it { should cmp 'true' }
        end
        describe 'Validating if a Certificate OCSP URL has been configured' do
          subject { auth['ocspURL'] }
          it { should_not cmp nil }
        end
      end
    end
  end
end
