control 'VCFA-9X-000262' do
  title 'VMware Cloud Foundation Operations must activate certificate validation.'
  desc  "
    A certificate's certification path is the path from the end entity certificate to a trusted root certification authority (CA). Certification path validation is necessary for a relying party to make an informed decision regarding acceptance of an end entity certificate.

    Certification path validation includes checks such as certificate issuer trust, time validity, and revocation status for each certificate in the certification path. Revocation status information for CA and subject certificates in a certification path is commonly provided via certificate revocation lists (CRLs) or online certificate status protocol (OCSP) responses.
  "
  desc  'rationale', ''
  desc  'check', "
    From VCF Operations, go to Administration >> Global Settings >> System Settings.

    Verify the \"Activate Standard Certificate Validation\" setting is activated.

    If the \"Activate Standard Certificate Validation\" setting is not activated, this is a finding.
  "
  desc 'fix', "
    From VCF Operations, go to Administration >> Global Settings >> System Settings.

    Find the \"Activate Standard Certificate Validation\" setting and click on the \"Deactivated\" radio button to enable it and click \"Save\".
  "
  impact 0.5
  tag severity: 'medium'
  tag gtitle: 'SRG-APP-000605'
  tag gid: 'V-VCFA-9X-000262'
  tag rid: 'SV-VCFA-9X-000262'
  tag stig_id: 'VCFA-9X-000262'
  tag cci: ['CCI-000185']
  tag nist: ['IA-5 (2) (b) (1)']

  response = http("https://#{input('operations_apihostname')}/suite-api/api/deployment/config/globalsettings",
                  method: 'GET',
                  ssl_verify: false,
                  headers: { 'Content-Type' => 'application/json',
                             'Accept' => 'application/json',
                             'Authorization' => "OpsToken #{input('operations_apitoken')}" })

  describe response do
    its('status') { should cmp 200 }
  end

  unless response.status != 200
    keyvals = json(content: response.body)['keyValues']
    itemkey = keyvals.find { |item| item['key'] == 'ENABLE_CERTIFICATE_VALIDATION_STANDARD_WAY' }

    if itemkey
      describe 'Certificate Validation must be enabled' do
        subject { itemkey['values'] }
        it { should eq ['true'] }
      end
    else
      describe 'Certificate Validation key' do
        subject { itemkey }
        it { should_not be_nil }
      end
    end
  end
end
