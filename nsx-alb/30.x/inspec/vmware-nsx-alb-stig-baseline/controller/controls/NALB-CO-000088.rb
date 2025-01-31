control 'NALB-CO-000088' do
  title 'The NSX Advanced Load Balancer Controller must disable basic authentication to the API.'
  desc  "
    API calls from a client to the NSX ALB Controller must first be authenticated, either by HTTP session-based auth or HTTP basic auth. The use of HTTP basic authentication for API access is unrelated to the use of basic auth for clients accessing a virtual service in which the Service Engine is proxying the authentication.

    Authenticated API calls are still subject to normal auth settings, regardless of the method used. The user account used for authentication may be validated by the Controller via a local database or remote (such as LDAP), may be limited to a specific tenant, or have limited roles or access levels.
  "
  desc  'rationale', ''
  desc  'check', "
    Review the access settings to verify basic authentication to the API is disabled.

    From the NSX ALB Controller web interface go to Administration >> System Settings >> Access.

    If \"Basic Authentication\" is enabled, this is a finding.
  "
  desc 'fix', "
    To configure \"Basic Authentication\", do the following:

    From the NSX ALB Controller web interface go to Administration >> System Settings.

    Click the edit icon next to \"System Settings\".

    Uncheck the box next to \"Allow Basic Authentication\" and click Save.
  "
  impact 0.5
  tag severity: 'medium'
  tag gtitle: 'SRG-APP-000516-NDM-000317'
  tag gid: 'V-NALB-CO-000088'
  tag rid: 'SV-NALB-CO-000088'
  tag stig_id: 'NALB-CO-000088'
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']

  results = http("https://#{input('avicontroller')}/api/systemconfiguration",
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
    describe 'Allow basic authentication' do
      subject { resultsjson['portal_configuration']['allow_basic_authentication'] }
      it { should cmp false }
    end
  end
end
