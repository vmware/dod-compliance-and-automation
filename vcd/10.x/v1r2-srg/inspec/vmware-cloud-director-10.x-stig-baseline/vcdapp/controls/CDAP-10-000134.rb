control 'CDAP-10-000134' do
  title 'Expired and untrusted certificates must be removed from Cloud Director.'
  desc  "Cloud Director's trust store does not automatically clean up expired, revoked, or no longer trusted certificates automatically. These certificates should be periodically reviewed and removed if they are no longer suitable for use."
  desc  'rationale', ''
  desc  'check', "
    From the Cloud Director provider interface, go to Administration >> Certificate Management >> Trusted Certificates.

    Review the list of trusted certificates for any that are expired, revoked, or no longer needed and trusted.

    If any certificates are present that are expired, revoked, or no longer trusted, this is a finding.
  "
  desc 'fix', "
    From the Cloud Director provider interface, go to Administration >> Certificate Management >> Trusted Certificates.

    Select the target certificate then click Delete then Delete again on the confirmation screen.

    Note: It is critical that you verify a certificates usage before deleting it to avoid any disruption of services as certificates that are expired may still be in use for an active connection and should be updated before deleting the expired certificate.
  "
  impact 0.5
  tag severity: 'medium'
  tag gtitle: 'SRG-APP-000516-AS-000237'
  tag gid: 'V-CDAP-10-000134'
  tag rid: 'SV-CDAP-10-000134'
  tag stig_id: 'CDAP-10-000134'
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']

  trustedCerts = input('trustedCertificates')
  result = http("https://#{input('vcdURL')}/cloudapi/1.0.0/ssl/trustedCertificates",
                method: 'GET',
                headers: {
                  'Accept' => "#{input('apiVersion')}",
                  'Authorization' => "#{input('bearerToken')}"
                },
                ssl_verify: false)

  describe result do
    its('status') { should cmp 200 }
  end
  unless result.status != 200
    certs = JSON.parse(result.body)
    certs['values'].each do |cert|
      describe cert['alias'] do
        it { should be_in trustedCerts }
      end
    end
  end
end
