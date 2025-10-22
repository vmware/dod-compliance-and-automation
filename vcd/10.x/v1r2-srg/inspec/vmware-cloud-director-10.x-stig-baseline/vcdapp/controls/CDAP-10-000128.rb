control 'CDAP-10-000128' do
  title 'Cloud Director must enable FIPS mode for NSX Edge Gateways.'
  desc  "
    Cryptography is only as strong as the encryption modules/algorithms employed to encrypt the data. Use of weak or untested encryption algorithms undermines the purposes of utilizing encryption to protect data.

    NSX-v edge gateways support enabling FIPS mode on deployment. When you enable FIPS mode, any secure communication to or from the NSX-v edge uses cryptographic algorithms or protocols that are allowed by FIPS.
  "
  desc  'rationale', ''
  desc  'check', "
    If NSX-v is not being used as a network provider for Cloud Director, this is Not Applicable.

    From the Cloud Director provider interface, go to Administration >> Settings >> General >> Networking.

    View the \"FIPS Mode for Edge Gateways\" setting.

    If \"FIPS Mode for Edge Gateways\" is not enabled, this is a finding.
  "
  desc 'fix', "
    From the Cloud Director provider interface, go to Administration >> Settings >> General >> Networking.

    Click Edit.

    Enable the radio button next to \"Allow FIPS mode\" and click Save.
  "
  impact 0.5
  tag severity: 'medium'
  tag gtitle: 'SRG-APP-000516-AS-000237'
  tag gid: 'V-CDAP-10-000128'
  tag rid: 'SV-CDAP-10-000128'
  tag stig_id: 'CDAP-10-000128'
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']

  if input('useNsxv')
    result = http("https://#{input('vcdURL')}/api/admin/extension/settings/general",
                  method: 'GET',
                  headers: {
                    'accept' => "#{input('legacyApiVersion')}",
                    'Authorization' => "#{input('bearerToken')}"
                  },
                  ssl_verify: false)

    describe result do
      its('status') { should cmp 200 }
    end
    unless result.status != 200
      describe json(content: result.body) do
        its(['allowFipsModeForEdgeGateways']) { should cmp 'true' }
      end
    end
  else
    describe 'NSX-v not used for the network provider...skipping...' do
      skip 'NSX-v not used for the network provider...skipping...'
    end
  end
end
