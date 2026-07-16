control 'VCFA-9X-000373' do
  title 'VMware Cloud Foundation Automation must include only approved trust anchors in trust stores or certificate stores managed by the organization.'
  desc  'Public key infrastructure (PKI) certificates are certificates with visibility external to organizational systems and certificates related to the internal operations of systems, such as application-specific time services. In cryptographic systems with a hierarchical structure, a trust anchor is an authoritative source (i.e., a certificate authority) for which trust is assumed and not derived. A root certificate for a PKI system is an example of a trust anchor. A trust store or certificate store maintains a list of trusted root certificates.'
  desc  'rationale', ''
  desc  'check', "
    If VCF Automation is not deployed, this is not applicable.

    From the VCF Automation Provider interface, go to Administration >> Certificate Management >> Trusted Certificates.

    Review the configured trusted certificates for any unknown trusted root certificates.

    If there are any unknown or unapproved trusted root certificates present, this is a finding.

    If any required internal certificate authorities are present, this is NOT a finding.
  "
  desc 'fix', "
    From the VCF Automation Provider interface, go to Administration >> Certificate Management >> Trusted Certificates.

    Locate the unapproved trusted root certificate in the list.

    Click the menu button next to the target and select Delete and click \"Delete\" to confirm the removal.

    Note: Internal certificate authorities will be present and should not be removed.
  "
  impact 0.5
  tag severity: 'medium'
  tag gtitle: 'SRG-APP-000910'
  tag gid: 'V-VCFA-9X-000373'
  tag rid: 'SV-VCFA-9X-000373'
  tag stig_id: 'VCFA-9X-000373'
  tag cci: ['CCI-004909']
  tag nist: ['SC-17 b']

  if input('automation_deployed')
    result = http("https://#{input('automation_url')}/cloudapi/1.0.0/ssl/trustedCertificates",
                  method: 'GET',
                  headers: {
                    'Accept' => "#{input('automation_apiVersion')}",
                    'Authorization' => "Bearer #{input('automation_sessionToken')}"
                  },
                  ssl_verify: false)

    describe result do
      its('status') { should cmp 200 }
    end
    unless result.status != 200
      trustedcerts = JSON.parse(result.body)
      trustedcerts = trustedcerts['values']
      if trustedcerts.blank?
        describe 'No trusted certificates found. Troubleshoot issue and rerun audit.' do
          skip 'No trusted certificates found. Troubleshoot issue and rerun audit.'
        end
      else
        trustedcerts.each do |trustedcert|
          describe "Trusted certificate authority with alias: #{trustedcert['alias']}" do
            subject { x509_certificate(content: trustedcert['certificate']) }
            its('issuer.CN') { should be_in input('automation_trustedCertificateCNs') }
          end
        end
      end
    end
  else
    impact 0.0
    describe 'VCF Automation is not deployed in the target environment. This control is N/A.' do
      skip 'VCF Automation is not deployed in the target environment. This control is N/A.'
    end
  end
end
