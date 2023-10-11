control 'NALB-CO-000079' do
  title 'The NSX Advanced Load Balancer Controller must be configured to protect against known types of denial-of-service (DoS) attacks by configuring an account lock timeout.'
  desc  "
    DoS is a condition when a resource is not available for legitimate users. When this occurs, the organization either cannot accomplish its mission or must operate at degraded capacity.

    This requirement addresses the configuration of network devices to mitigate the impact of DoS attacks that have occurred or are ongoing on device availability. For each network device, known and potential DoS attacks must be identified and solutions for each type implemented. A variety of technologies exist to limit or, in some cases, eliminate the effects of DoS attacks (e.g., limiting processes or restricting the number of sessions the device opens at one time). Employing increased capacity and bandwidth, combined with service redundancy, may reduce the susceptibility to some DoS attacks.

    The security safeguards cannot be defined at the DoD level because they vary according to the capabilities of the individual network devices and the security controls applied on the adjacent networks (for example, firewalls performing packet filtering to block DoS attacks).
  "
  desc  'rationale', ''
  desc  'check', "
    Review the default user account profile to verify account lock timeout is set to 0 and verify it is applied to all local users.

    From the NSX ALB Controller web interface go to Administration >> Accounts >> User Profiles.

    Select edit on the \"Default-User-Account-Profile\" to view the configuration.

    If \"Account Lock Timeout\" is not set to 0, this is a finding.

    From the NSX ALB Controller web interface go to Administration >> Accounts >> Users.

    Verify each user has the \"Default-User-Account-Profile\" applied.

    If the \"Default-User-Account-Profile\" is not applied to all users, this is a finding.
  "
  desc 'fix', "
    To update the \"Default-User-Account-Profile\" profile do the following:

    From the NSX ALB Controller web interface go to Administration >> Accounts >> User Profiles.

    Click the edit icon next to the \"Default-User-Account-Profile\" profile.

    Update the \"Account Lock Timeout\" value to 0 and click Save.

    To update a user to use the \"Default-User-Account-Profile\" profile do the following:

    From the NSX ALB Controller web interface go to Administration >> Accounts >> Users.

    Click the edit icon next to the user.

    Update the \"User Profile\" setting to \"Default-User-Account-Profile\" and click Save.
  "
  impact 0.5
  tag severity: 'medium'
  tag gtitle: 'SRG-APP-000435-NDM-000315'
  tag gid: 'V-NALB-CO-000079'
  tag rid: 'SV-NALB-CO-000079'
  tag stig_id: 'NALB-CO-000079'
  tag cci: ['CCI-002385']
  tag nist: ['SC-5']

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
        describe 'Account lock timeout' do
          subject { result['account_lock_timeout'] }
          it { should cmp 0 }
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
