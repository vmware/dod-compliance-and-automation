control 'VLMA-8X-000009' do
  title 'VMware Aria Suite Lifecycle must not provide environment information to third parties.'
  desc  'Providing technical details about an environments infrastructure to third parties could unknowningly expose sensitive information to bad actors if intercepted.'
  desc  'rationale', ''
  desc  'check', "
    Login to VMware Aria Suite Lifecycle as the admin@local account..

    Click on Lifecycle Operations >> Settings >> System Details

    If the Customer Experience Improvement Program is not disabled, this is a finding.
  "
  desc 'fix', "
    Login to VMware Aria Suite Lifecycle as the admin@local account.

    Click on Lifecycle Operations >> Settings >> System Details

    Click Quit next to Customer Experience Improvement Program.
  "
  impact 0.5
  tag severity: 'medium'
  tag gtitle: 'SRG-APP-000516-AS-000237'
  tag gid: 'V-VLMA-8X-000009'
  tag rid: 'SV-VLMA-8X-000009'
  tag stig_id: 'VLMA-8X-000009'
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']

  cred = Base64.encode64("#{input('username')}:#{input('password')}")

  response = http("https://#{input('hostname')}/lcm/lcops/api/v2/settings/system-details/telemetry",
                  method: 'GET',
                  headers: {
                    'Content-Type' => 'application/json',
                    'Accept' => 'application/json',
                    'Authorization' => "Basic #{cred}"
                  },
                  ssl_verify: false)

  describe response do
    its('status') { should cmp 200 }
  end

  unless response.status != 200
    result = JSON.parse(response.body)

    describe result['telemetryEnabled'] do
      it { should cmp false }
    end
  end
end
