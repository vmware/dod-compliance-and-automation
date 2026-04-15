control 'NALB-CO-000012' do
  title 'The NSX Advanced Load Balancer Controller must be configured to enforce the limit of three consecutive invalid logon attempts.'
  desc  'By limiting the number of failed login attempts, the risk of unauthorized system access via user password guessing, otherwise known as brute-forcing, is reduced.'
  desc  'rationale', ''
  desc  'check', "
    Review the default user account profile to verify that it enforces the limit of three consecutive invalid login attempts and is applied to all local users.

    From the NSX ALB Controller web interface go to Administration >> Accounts >> User Profiles.

    Select edit on the \"Default-User-Account-Profile\" to view the configuration.

    If \"Max Login Failure Count\" is not set to 3 or less, this is a finding.

    From the NSX ALB Controller web interface go to Administration >> Accounts >> Users.

    Verify each user has the \"Default-User-Account-Profile\" applied.

    If the \"Default-User-Account-Profile\" is not applied to all users, this is a finding.
  "
  desc 'fix', "
    To update the \"Default-User-Account-Profile\" profile do the following:

    From the NSX ALB Controller web interface go to Administration >> Accounts >> User Profiles.

    Click the edit icon next to the \"Default-User-Account-Profile\" profile.

    Update the \"Max Login Failure Count\" value to 3 and click Save.

    To update a user to use the \"Default-User-Account-Profile\" profile do the following:

    From the NSX ALB Controller web interface go to Administration >> Accounts >> Users.

    Click the edit icon next to the user.

    Update the \"User Profile\" setting to \"Default-User-Account-Profile\" and click Save.
  "
  impact 0.5
  tag severity: 'medium'
  tag gtitle: 'SRG-APP-000065-NDM-000214'
  tag gid: 'V-NALB-CO-000012'
  tag rid: 'SV-NALB-CO-000012'
  tag stig_id: 'NALB-CO-000012'
  tag cci: ['CCI-000044']
  tag nist: ['AC-7 a']

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
        describe 'Max Login Failure Count' do
          subject { result['max_login_failure_count'] }
          it { should cmp <= 3 }
          it { should_not cmp 0 }
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
