control 'CFAP-5X-000122' do
  title 'The SDDC Manager must use DOD- or CNSS-approved PKI Class 3 or Class 4 certificates.'
  desc  'Class 3 PKI certificates are used for servers and software signing rather than for identifying individuals. Class 4 certificates are used for business-to-business transactions. Utilizing unapproved certificates not issued or approved by DOD or CNS creates an integrity risk. The application server must utilize approved DOD or CNS Class 3 or Class 4 certificates for software signing and business-to-business transactions.'
  desc  'rationale', ''
  desc  'check', "
    From the SDDC Manager UI, navigate to Inventory >> Workload Domains.

    Select the management workload domain.

    Go to the certificates tab and expand the \"sddcmanager\" resource type and view the \"issuedBy\" field of the current certificate.

    If the issuer specified is not a DOD approved certificate authority, this is a finding.
  "
  desc 'fix', "
    To update the SDDC Manager certificate perform the following steps:

    From the SDDC Manager UI, navigate to Inventory >> Workload Domains.

    Select the management workload domain.

    Go to the certificates tab and check the box for the \"sddcmanager\" resource type.

    Click \"Generate CSRS\" then follow the prompts to generate a certificate signing request for the SDDC Manager.

    Click \"Download CSR\" then follow your organizations process to request a new PEMcertificate from an authorized certificate authority.

    Once a new certificate is received do the following:

    From the SDDC Manager UI, navigate to Inventory >> Workload Domains.

    Select the management workload domain.

    Go to the certificates tab and click \"Upload and Install Certificates\".

    Select the SDDC Manager resource and upload the new certificate by either pasting the text or uploading the file then clicking \"Install\".

    Note: If legacy certificate management is enabled, the steps for certificate replacement will differ.
  "
  impact 0.5
  tag severity: 'medium'
  tag gtitle: 'SRG-APP-000514-AS-000137'
  tag gid: 'V-CFAP-5X-000122'
  tag rid: 'SV-CFAP-5X-000122'
  tag stig_id: 'CFAP-5X-000122'
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
    if domains.empty?
      describe 'No domains returned.' do
        subject { domains }
        it { should_not be_empty }
      end
    else
      domains['elements'].each do |domain|
        next unless domain['type'] == 'MANAGEMENT'
        name = domain['name']
        certificates = http("https://#{input('sddcManager')}/v1/domains/#{name}/resource-certificates",
                            method: 'GET',
                            headers: {
                              'Accept' => 'application/json',
                              'Authorization' => "#{input('bearerToken')}"
                            },
                            ssl_verify: false)

        describe certificates do
          its('status') { should cmp 200 }
        end
        certs = JSON.parse(certificates.body)
        if certs.empty?
          describe 'No certificates returned.' do
            subject { certs }
            it { should_not be_empty }
          end
        else
          sddcmanagercertfound = false
          certs['elements'].each do |cert|
            next unless cert['resourceType'] == 'SDDC_MANAGER'
            describe "Checking certificate for resource: #{cert['resourceName']}. Its" do
              subject { json(content: cert.to_json) }
              its('issuedBy') { should match /O=U\.S\. Government/ }
              its('issuedBy') { should match /OU=DoD/ }
            end
            sddcmanagercertfound = true
          end
          unless sddcmanagercertfound
            describe 'No certificate found for SDDC Manager.' do
              subject { sddcmanagercertfound }
              it { should cmp 'true' }
            end
          end
        end
      end
    end
  end
end
