control 'VCFA-9X-000350' do
  title 'VMware Cloud Foundation Operations must enable credential ownership enforcement.'
  desc  'VCF Operations allows the creation of credentials for use with adapters when setting up integrations with other products. The credentials for these integrations are sensitive and should not be accessible except to those who created them.'
  desc  'rationale', ''
  desc  'check', "
    From VCF Operations, go to Administration >> Global Settings >> System Settings.

    Verify the \"Credential ownership enforcement\" setting is activated.

    If the \"Credential ownership enforcement\" setting is not activated, this is a finding.
  "
  desc 'fix', "
    From VCF Operations, go to Administration >> Global Settings >> System Settings.

    Find the \"Credential ownership enforcement\" setting and click on the \"Deactivated\" radio button to enable it and click \"Save\".
  "
  impact 0.5
  tag severity: 'medium'
  tag gtitle: 'SRG-APP-000516'
  tag gid: 'V-VCFA-9X-000350'
  tag rid: 'SV-VCFA-9X-000350'
  tag stig_id: 'VCFA-9X-000350'
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']

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
    itemkey = keyvals.find { |item| item['key'] == 'ACTIVATE_CREDENTIAL_OWNERSHIP' }

    if itemkey
      describe 'Credential ownership enforcement must be enabled' do
        subject { itemkey['values'] }
        it { should eq ['true'] }
      end
    else
      describe 'Credential ownership enforcement key' do
        subject { itemkey }
        it { should_not be_nil }
      end
    end
  end
end
