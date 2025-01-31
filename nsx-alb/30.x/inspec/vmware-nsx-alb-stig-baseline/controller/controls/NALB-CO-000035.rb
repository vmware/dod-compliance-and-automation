control 'NALB-CO-000035' do
  title 'The NSX Advanced Load Balancer Controller must be configured with only one local account to be used as the account of last resort in the event the authentication server is unavailable.'
  desc  "
    Authentication for administrative (privileged level) access to the device is required at all times. An account can be created on the device's local database for use when the authentication server is down or connectivity between the device and the authentication server is not operable. This account is referred to as the account of last resort since it is intended to be used as a last resort and when immediate administrative access is absolutely necessary.

    The account of last resort logon credentials must be stored in a sealed envelope and kept in a safe. The safe must be periodically audited to verify the envelope remains sealed. The signature of the auditor and the date of the audit should be added to the envelope as a record. Administrators should secure the credentials and disable the root account (if possible) when not needed for system administration functions.
  "
  desc  'rationale', ''
  desc  'check', "
    Review the user accounts to verify if only the default local user \"admin\" account exists.

    From the NSX ALB Controller web interface go to Administration >> Accounts >> Users.

    If there are any local accounts other than \"admin\", this is a finding.
  "
  desc 'fix', "
    To delete local users other than admin, do the following:

    From the NSX ALB Controller web interface go to Administration >> Accounts >> Users.

    Select the user and click Delete.
  "
  impact 0.5
  tag severity: 'medium'
  tag gtitle: 'SRG-APP-000148-NDM-000346'
  tag gid: 'V-NALB-CO-000035'
  tag rid: 'SV-NALB-CO-000035'
  tag stig_id: 'NALB-CO-000035'
  tag cci: ['CCI-001358']
  tag nist: ['AC-2 (7) (a)']

  # Get all local users
  users = http("https://#{input('avicontroller')}/api/user?local=true",
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
        describe "User: #{userjson['username']}" do
          subject { userjson['username'] }
          it { should cmp 'admin' }
        end
      end
    end
  end
end
