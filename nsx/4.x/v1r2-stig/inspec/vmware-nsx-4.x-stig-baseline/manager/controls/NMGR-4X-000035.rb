control 'NMGR-4X-000035' do
  title 'The NSX Manager must be configured with only one local account to be used as the account of last resort in the event the authentication server is unavailable.'
  desc "Authentication for administrative (privileged level) access to the device is required at all times. An account can be created on the device's local database for use when the authentication server is down or connectivity between the device and the authentication server is not operable. This account is referred to as the account of last resort since it is intended to be used as a last resort and when immediate administrative access is absolutely necessary.

The account of last resort logon credentials must be stored in a sealed envelope and kept in a safe. The safe must be periodically audited to verify the envelope remains sealed. The signature of the auditor and the date of the audit should be added to the envelope as a record. Administrators should secure the credentials and disable the root account (if possible) when not needed for system administration functions."
  desc 'check', 'From the NSX Manager web interface, go to the System >> Settings >> User Management >> Local Users and view the status column.

If any local account other than the account of last resort are active, this is a finding.'
  desc 'fix', 'From the NSX Manager web interface, go to the System >> Settings >> User Management >> Local Users.

Select the menu drop down next to any local user on the list except for the "admin" account. Click modify and click "Deactivate User".'
  impact 0.5
  ref 'DPMS Target VMware NSX 4.x Manager NDM'
  tag check_id: 'C-69230r994160_chk'
  tag severity: 'medium'
  tag gid: 'V-265313'
  tag rid: 'SV-265313r1051115_rule'
  tag stig_id: 'NMGR-4X-000035'
  tag gtitle: 'SRG-APP-000148-NDM-000346'
  tag fix_id: 'F-69138r994161_fix'
  tag 'documentable'
  tag cci: ['CCI-001358']
  tag nist: ['AC-2 (7) (a)']

  result = http("https://#{input('nsxManager')}/api/v1/node/users",
                method: 'GET',
                headers: {
                  'Accept' => 'application/json',
                  'X-XSRF-TOKEN' => "#{input('sessionToken')}",
                  'Cookie' => "#{input('sessionCookieId')}"
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
