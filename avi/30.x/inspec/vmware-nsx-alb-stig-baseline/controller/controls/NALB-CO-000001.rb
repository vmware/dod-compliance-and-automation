control 'NALB-CO-000001' do
  title 'The NSX Advanced Load Balancer Controller must limit the number of concurrent sessions to 5 for each administrator account and/or administrator account type.'
  desc  "
    Device management includes the ability to control the number of administrators and management sessions that manage a device. Limiting the number of allowed administrators and sessions per administrator based on account type, role, or access type is helpful in limiting risks related to DoS attacks.

    This requirement addresses concurrent sessions for administrative accounts and does not address concurrent sessions by a single administrator via multiple administrative accounts.
  "
  desc  'rationale', ''
  desc  'check', "
    Review the default user account profile to verify max concurrent sessions is set to 5 and verify it is applied to all local users.

    From the NSX ALB Controller web interface go to Administration >> Accounts >> User Profiles.

    Select edit on the \"Default-User-Account-Profile\" to view the configuration.

    If \"Max Concurrent Sessions\" is not set to 5 or less, this is a finding.

    From the NSX ALB Controller web interface go to Administration >> Accounts >> Users.

    Verify each user has the \"Default-User-Account-Profile\" applied.

    If the \"Default-User-Account-Profile\" is not applied to all users, this is a finding.
  "
  desc 'fix', "
    To update the \"Default-User-Account-Profile\" profile do the following:

    From the NSX ALB Controller web interface go to Administration >> Accounts >> User Profiles.

    Click the edit icon next to the \"Default-User-Account-Profile\" profile.

    Update the \"Max Concurrent Sessions\" value to 5 and click Save.

    To update a user to use the \"Default-User-Account-Profile\" profile do the following:

    From the NSX ALB Controller web interface go to Administration >> Accounts >> Users.

    Click the edit icon next to the user.

    Update the \"User Profile\" setting to \"Default-User-Account-Profile\" and click Save.
  "
  impact 0.5
  tag severity: 'medium'
  tag gtitle: 'SRG-APP-000001-NDM-000200'
  tag gid: 'V-NALB-CO-000001'
  tag rid: 'SV-NALB-CO-000001'
  tag stig_id: 'NALB-CO-000001'
  tag cci: ['CCI-000054']
  tag nist: ['AC-10']

  # Check Default User Account Profile
  results = http("https://#{input('avicontroller')}/api/useraccountprofile?name=Default-User-Account-Profile",
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
    if resultsjson['results'] == []
      describe 'Default User Account Profile not found...skipping.' do
        skip 'Default User Account Profile not found...skipping.'
      end
    else
      resultsjson['results'].each do |result|
        describe 'Profile name' do
          subject { result['name'] }
          it { should cmp 'Default-User-Account-Profile' }
        end
        describe 'Max Concurrent Sessions' do
          subject { result['max_concurrent_sessions'] }
          it { should cmp 5 }
        end
      end
      duapurl = resultsjson['results'][0]['url']
    end
  end

  # Check each user is using the Default User Account Profile
  users = http("https://#{input('avicontroller')}/api/user",
                method: 'GET',
                headers: {
                  'Accept-Encoding' => 'application/json',
                  'X-Avi-Version' => "#{input('aviversion')}",
                  'Cookie' => "sessionid=#{input('sessionCookieId')}",
                },
                ssl_verify: false)

  describe users do
    its('status') { should cmp 200 }
  end

  unless users.status != 200
    usersjson = JSON.parse(users.body)
    if usersjson['results'] == []
      describe 'No users found...skipping.' do
        skip 'No users found...skipping.'
      end
    else
      usersjson['results'].each do |user|
        userjson = json(content: user.to_json)
        describe "User account profile for user #{userjson['username']}" do
          subject { userjson['user_profile_ref'] }
          it { should cmp duapurl }
        end
      end
    end
  end
end
