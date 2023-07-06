control 'TNDM-3X-000100' do
  title 'The NSX-T Manager must disable unused local accounts.'
  desc  'Prior to NSX-T 3.1 and earlier, there are three local accounts: root, admin, and audit. These local accounts could not be disabled and no additional accounts could be created. Starting in NSX-T 3.1.1, there are two additional guest user accounts: guestuser1 and guestuser2. The local accounts for audit and guest users are disabled by default, but can be deactivated once active; however, admin and root accounts cannot be disabled. These accounts should remain disabled and unique non-local user accounts should be used instead.'
  desc  'rationale', ''
  desc  'check', "
    If NSX-T is not at least version 3.1.1, this is not applicable.

    From the NSX-T Manager web interface, go to the System >> Users and Roles >> Local Users and view the status column.

    If the audit, guestuser1, or guestuser2 local accounts are active, this is a finding.
  "
  desc 'fix', "
    From the NSX-T Manager web interface, go to the System >> Users and Roles >> Local Users.

    Select the menu drop down next to the user to modify and click \"Deactivate User\".
  "
  impact 0.5
  tag severity: 'medium'
  tag gtitle: 'SRG-APP-000142-NDM-000245'
  tag gid: 'V-251797'
  tag rid: 'SV-251797r810394_rule'
  tag stig_id: 'TNDM-3X-000100'
  tag fix_id: 'F-55211r810393_fix'
  tag cci: ['CCI-000382']
  tag nist: ['CM-7 b']

  result = http("https://#{input('nsxManager')}/api/v1/node/users",
              method: 'GET',
              headers: {
                'Accept' => 'application/json',
                'X-XSRF-TOKEN' => "#{input('sessionToken')}",
                'Cookie' => "#{input('sessionCookieId')}",
                },
              ssl_verify: false)

  describe result do
    its('status') { should cmp 200 }
  end
  unless result.status != 200
    users = JSON.parse(result.body)
    users['results'].each do |user|
      next unless user['username'] == 'audit' || user['username'] == 'guestuser1' || user['username'] == 'guestuser2'
      describe "User #{user['username']} status" do
        subject { json(content: user.to_json)['status'] }
        it { should cmp 'NOT_ACTIVATED' }
      end
    end
  end
end
