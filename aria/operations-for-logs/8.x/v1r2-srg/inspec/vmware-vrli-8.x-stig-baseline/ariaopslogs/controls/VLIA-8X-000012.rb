control 'VLIA-8X-000012' do
  title 'VMware Aria Operations for Logs must not provide environment information to third parties.'
  desc  'Providing technical details regarding environment infrastructure to third parties could unknowingly expose sensitive information to bad actors if intercepted.'
  desc  'rationale', ''
  desc  'check', "
    Login to VMware Aria Operations for Logs as an administrator.

    In the slide-out menu on the left, choose Configuration >> General.

    If \"Usage Reporting\" is not disabled, this is a finding.
  "
  desc 'fix', "
    Login to VMware Aria Operations for Logs as an administrator.

    In the slide-out menu on the left, choose Configuration >> General.

    Uncheck the box next to \"Usage Reporting\" and click Save.
  "
  impact 0.5
  tag severity: 'medium'
  tag gtitle: 'SRG-APP-000516-AU-000410'
  tag gid: 'V-VLIA-8X-000012'
  tag rid: 'SV-VLIA-8X-000012'
  tag stig_id: 'VLIA-8X-000012'
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']

  token = http("https://#{input('apipath')}/sessions",
               method: 'POST',
               headers: {
                 'Content-Type' => 'application/json',
                 'Accept' => 'application/json'
               },
               data: "{\"username\":\"#{input('username')}\",\"password\":\"#{input('password')}\",\"provider\":\"Local\"}",
               ssl_verify: false)

  describe token do
    its('status') { should cmp 200 }
  end

  unless token.status != 200
    sessID = JSON.parse(token.body)['sessionId']

    response = http("https://#{input('apipath')}/ceip",
                    method: 'GET',
                    headers: {
                      'Content-Type' => 'application/json',
                      'Accept' => 'application/json',
                      'Authorization' => "Bearer #{sessID}"
                    },
                    ssl_verify: false)

    describe response do
      its('status') { should cmp 200 }
    end

    unless response.status != 200
      describe json(content: response.body) do
        its(['feedback']) { should cmp 'false' }
      end
    end
  end
end
