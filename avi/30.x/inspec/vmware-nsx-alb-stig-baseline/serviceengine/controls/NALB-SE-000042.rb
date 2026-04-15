control 'NALB-SE-000042' do
  title 'The NSX Advanced Load Balancer that provides intermediary services for TLS must validate certificates used for TLS functions by performing RFC 5280-compliant certification path validation.'
  desc  "
    A certificate's certification path is the path from the end entity certificate to a trusted root certification authority (CA). Certification path validation is necessary for a relying party to make an informed decision regarding acceptance of an end entity certificate.

    Certification path validation includes checks such as certificate issuer trust, time validity and revocation status for each certificate in the certification path. Revocation status information for CA and subject certificates in a certification path is commonly provided via certificate revocation lists (CRLs) or online certificate status protocol (OCSP) responses.
  "
  desc  'rationale', ''
  desc  'check', "
    If OCSP is not available in the environment, this is Not Applicable.

    Review each \"Root/Intermediate CA\" to ensure OCSP Stapling is enabled.

    From the NSX ALB Controller web interface go to Templates >> Security >> SSL/TLS Certificates.

    Select the edit icon for each certificate listed under \"Root/Intermediate CA\" to view the configuration under the OCSP section.

    If \"Enable OCSP Stapling\" is not enabled, this is a finding.

    Note: OCSP stapling cannot be enabled for self-signed certificates.
  "
  desc 'fix', "
    To enable the \"OCSP Stapling\" do the following:

    From the NSX ALB Controller web interface go to Templates >> Security >> SSL/TLS Certificates >> Under Root/Intermediate CA.

    Click the edit on the available \"Certificate Authority\".

    Select \"Enable OCSP Stapling\" and click Save.
  "
  impact 0.5
  tag severity: 'medium'
  tag gtitle: 'SRG-NET-000164-ALG-000100'
  tag gid: 'V-NALB-SE-000042'
  tag rid: 'SV-NALB-SE-000042'
  tag stig_id: 'NALB-SE-000042'
  tag cci: ['CCI-000185']
  tag nist: ['IA-5 (2) (a)']

  ocspavailable = input('ocspavailable')
  if ocspavailable
    results = http("https://#{input('avicontroller')}/api/sslkeyandcertificate",
                    method: 'GET',
                    headers: {
                      'Accept-Encoding' => 'application/json',
                      'X-Avi-Version' => "#{input('aviversion')}",
                      'Cookie' => "sessionid=#{input('sessionCookieId')}",
                    },
                    ssl_verify: false)

    describe results do
      its('status') { should cmp 200 }
    end

    unless results.status != 200
      resultsjson = JSON.parse(results.body)
      # To count if we do not find an eligible cert to inspect
      certcount = 0
      resultsjson['results'].each do |sslcert|
        next unless sslcert['type'] == 'SSL_CERTIFICATE_TYPE_CA' && sslcert['certificate']['self_signed'] == false
        describe 'OCSP Stapling' do
          subject { sslcert['enable_ocsp_stapling'] }
          it { should cmp true }
        end
        # Increment # of elible certs found
        certcount += 1
      end
      unless certcount != 0
        impact 0.0
        describe 'No CA Certificates found that were not self-signed.' do
          skip 'No CA Certificates found that were not self-signed.'
        end
      end
    end
  else
    impact 0.0
    describe 'OCSP not available in the environment so this is not applicable.' do
      skip 'OCSP not available in the environment so this is not applicable.'
    end
  end
end
