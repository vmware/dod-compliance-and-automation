control 'CFAP-4X-000004' do
  title 'The SDDC Manager must use DOD- or CNSS-approved PKI Class 3 or Class 4 certificates.'
  desc  'Class 3 PKI certificates are used for servers and software signing rather than for identifying individuals. Class 4 certificates are used for business-to-business transactions. Utilizing unapproved certificates not issued or approved by DOD or CNS creates an integrity risk. The application server must utilize approved DOD or CNS Class 3 or Class 4 certificates for software signing and business-to-business transactions.'
  desc  'rationale', ''
  desc  'check', "
    From the SDDC Manager UI, navigate to Inventory >> Workload Domains select the management workload domain.

    Go to the security tab and expand the \"sddcmanager\" resource type and view the \"issuedBy\" field of the current certificate.

    If the issuer specified is not a DOD approved certificate authority, this is a finding.
  "
  desc 'fix', "
    To update the SDDC Manager certificate reference the documentation at the following URL:

    https://docs.vmware.com/en/VMware-Cloud-Foundation/4.5/com.vmware.vcf.vxrail.doc/GUID-2A1E7307-84EA-4345-9518-198718E6A8A6.html
  "
  impact 0.5
  tag severity: 'medium'
  tag gtitle: 'SRG-APP-000514-AS-000137'
  tag gid: 'V-CFAP-4X-000004'
  tag rid: 'SV-CFAP-4X-000004'
  tag stig_id: 'CFAP-4X-000004'
  tag cci: ['CCI-002450']
  tag nist: ['SC-13']

  result = http("https://#{input('sddcManager')}/v1/domains",
                method: 'GET',
                headers: {
                  'Accept' => 'application/json',
                  'Authorization' => "#{input('bearerToken')}"
                },
                ssl_verify: false)

  describe result do
    its('status') { should cmp 200 }
  end
  unless result.status != 200
    domains = JSON.parse(result.body)
    domains['elements'].each do |domain|
      next unless domain['type'] != 'MANAGEMENT'
      name = domain['name']
      certificates = http("https://#{input('sddcManager')}/v1/domains/#{name}/resource-certificates",
                          method: 'GET',
                          headers: {
                            'Accept' => 'application/json',
                            'Authorization' => "#{input('bearerToken')}"
                          },
                          ssl_verify: false)

      certs = JSON.parse(certificates.body)
      certs['elements'].each do |cert|
        issuedTo = cert['issuedTo']
        describe json(content: cert.to_json) do
          its('issuedTo') { should cmp issuedTo }
          its('issuedBy') { should match /O=U\.S\. Government/ }
          its('issuedBy') { should match /OU=DoD/ }
        end
      end
    end
  end
end
