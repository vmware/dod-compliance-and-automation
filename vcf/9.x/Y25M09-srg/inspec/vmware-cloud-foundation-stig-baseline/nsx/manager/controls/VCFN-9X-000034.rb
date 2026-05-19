control 'VCFN-9X-000034' do
  title 'The VMware Cloud Foundation NSX Manager must be configured with only one local account to be used as the account of last resort in the event the authentication server is unavailable.'
  desc  "
    Authentication for administrative (privileged level) access to the device is required at all times. An account can be created on the device's local database for use when the authentication server is down or connectivity between the device and the authentication server is not operable. This account is referred to as the account of last resort since it is intended to be used as a last resort and when immediate administrative access is absolutely necessary.

    The account of last resort logon credentials must be stored in a sealed envelope and kept in a safe. The safe must be periodically audited to verify the envelope remains sealed. The signature of the auditor and the date of the audit should be added to the envelope as a record. Administrators should secure the credentials and disable the root account (if possible) when not needed for system administration functions.
  "
  desc  'rationale', ''
  desc  'check', "
    From the NSX Manager web interface, go to the System >> Settings >> User Management >> Local Users and view the status column.

    If the audit, guestuser1, or guestuser2 local accounts are active, this is a finding.
  "
  desc 'fix', "
    From the NSX Manager web interface, go to the System >> Settings >> User Management >> Local Users.

    Select the menu drop down next to the user to modify and click \"Deactivate User\".
  "
  impact 0.5
  tag severity: 'medium'
  tag gtitle: 'SRG-APP-000148-NDM-000346'
  tag gid: 'V-VCFN-9X-000034'
  tag rid: 'SV-VCFN-9X-000034'
  tag stig_id: 'VCFN-9X-000034'
  tag cci: ['CCI-001358', 'CCI-002111']
  tag nist: ['AC-2 (7) (a)', 'AC-2 a']

  result = http("https://#{input('nsx_managerAddress')}/api/v1/node/users",
                method: 'GET',
                headers: {
                  'Accept' => 'application/json',
                  'X-XSRF-TOKEN' => "#{input('nsx_sessionToken')}",
                  'Cookie' => "#{input('nsx_sessionCookieId')}"
                },
                ssl_verify: false)

  describe result do
    its('status') { should cmp 200 }
  end
  unless result.status != 200
    users = JSON.parse(result.body)
    if !users['results'].empty?
      users['results'].each do |user|
        next unless ['audit', 'guestuser1', 'guestuser2'].include?(user['username'])
        describe "User #{user['username']} status" do
          subject { json(content: user.to_json)['status'] }
          it { should cmp 'NOT_ACTIVATED' }
        end
      end
    else
      describe 'Unable to validate users. No results returned.' do
        subject { users['results'] }
        it { should_not be_empty }
      end
    end
  end
end
