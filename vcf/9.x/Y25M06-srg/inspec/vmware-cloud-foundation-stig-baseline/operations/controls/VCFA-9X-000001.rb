control 'VCFA-9X-000001' do
  title 'VMware Cloud Foundation Operations must limit the number of concurrent sessions.'
  desc  'Application management includes the ability to control the number of users and user sessions that use an application. Limiting the number of allowed users and sessions per user is helpful in limiting risks related to denial-of-service (DoS) attacks.'
  desc  'rationale', ''
  desc  'check', "
    From VCF Operations, go to Administration >> Global Settings >> User Access.

    Verify the \"Concurrent UI login sessions\" setting is deactivated.

    If the \"Concurrent UI login sessions\" setting is not deactivated, this is a finding.
  "
  desc 'fix', "
    From VCF Operations, go to Administration >> Global Settings >> User Access.

    Find the \"Concurrent UI login sessions\" setting and click on the \"Activated\" radio button to disable it and click \"Save\".
  "
  impact 0.5
  tag severity: 'medium'
  tag gtitle: 'SRG-APP-000001'
  tag gid: 'V-VCFA-9X-000001'
  tag rid: 'SV-VCFA-9X-000001'
  tag stig_id: 'VCFA-9X-000001'
  tag cci: ['CCI-000054']
  tag nist: ['AC-10']

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
    itemkey = keyvals.find { |item| item['key'] == 'ALLOW_CONCURRENT_LOGIN_SESSIONS' }

    if itemkey
      describe 'Allow Concurrent Login Sessions' do
        subject { itemkey['values'] }
        it { should eq ['false'] }
      end
    else
      describe 'Concurrent Login Sessions setting' do
        subject { itemkey }
        it { should_not be_nil }
      end
    end
  end
end
