control 'NALB-CO-000099' do
  title 'The NSX Advanced Load Balancer Controller must expire credentials after 90 days.'
  desc  'The admin can choose to expire user credentials after a configurable number of days. Once credentials have expired, all API calls are going to error out. Only API/user account is supported at this point, to enable the user to change the password. If the user has configured an email address, the “Forgot Password” workflow can also be followed at this point to reset the password.'
  desc  'rationale', ''
  desc  'check', "
    Review the default user account profile to verify the credential timeout threshold is set to 90 and verify it is applied to all local users.

    From the NSX ALB Controller web interface go to Administration >> Accounts >> User Profiles.

    Select edit on the \"Default-User-Account-Profile\" to view the configuration.

    If \"Credential Timeout Threshold\" is not set to 90 or less, this is a finding.

    From the NSX ALB Controller web interface go to Administration >> Accounts >> Users.

    Verify each user has the \"Default-User-Account-Profile\" applied.

    If the \"Default-User-Account-Profile\" is not applied to all users, this is a finding.
  "
  desc 'fix', "
    To update the \"Default-User-Account-Profile\" profile do the following:

    From the NSX ALB Controller web interface go to Administration >> Accounts >> User Profiles.

    Click the edit icon next to the \"Default-User-Account-Profile\" profile.

    Update the \"Credential Timeout Threshold\" value to 90 and click Save.

    To update a user to use the \"Default-User-Account-Profile\" profile do the following:

    From the NSX ALB Controller web interface go to Administration >> Accounts >> Users.

    Click the edit icon next to the user.

    Update the \"User Profile\" setting to \"Default-User-Account-Profile\" and click Save.
  "
  impact 0.5
  tag severity: 'medium'
  tag gtitle: 'SRG-APP-000516-NDM-000317'
  tag gid: 'V-NALB-CO-000099'
  tag rid: 'SV-NALB-CO-000099'
  tag stig_id: 'NALB-CO-000099'
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']

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
        describe 'Credential timeout threshold' do
          subject { result['credentials_timeout_threshold'] }
          it { should cmp <= 90 }
          it { should cmp > 0 }
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
