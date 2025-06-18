control 'VCFA-9X-000354' do
  title 'VMware Cloud Foundation SDDC Manager assigned roles and permissions must be verified.'
  desc  'Users and service accounts must only be assigned privileges they require. Least privilege requires that these privileges must only be assigned if needed to reduce risk of confidentiality, availability, or integrity loss.'
  desc  'rationale', ''
  desc  'check', "
    From the SDDC Manager UI, go to Administration >> Single Sign On.

    Review the Users and Groups assigned a role in SDDC Manager and verify the appropriate roles are assigned.

    If any users or groups are assigned a role that includes more access than needed, this is a finding.
  "
  desc 'fix', "
    To remove a user or group, do the following:

    From the SDDC Manager UI, go to Administration >> Single Sign On.

    Select the user or group in question and click \"Remove\".

    Click \"Delete\" to confirm the removal.

    Note: To update a user's or group's role they must first be removed then added back to the system.
  "
  impact 0.5
  tag severity: 'medium'
  tag gtitle: 'SRG-APP-000211'
  tag gid: 'V-VCFA-9X-000354'
  tag rid: 'SV-VCFA-9X-000354'
  tag stig_id: 'VCFA-9X-000354'
  tag cci: ['CCI-001082']
  tag nist: ['SC-2']

  sddcmgr_authorizedPermissions = input('sddcmgr_authorizedPermissions')
  roles = http("https://#{input('sddcmgr_url')}/v1/roles",
               method: 'GET',
               headers: {
                 'Accept' => 'application/json',
                 'Authorization' => "Bearer #{input('sddcmgr_sessionToken')}"
               },
               ssl_verify: false)

  users = http("https://#{input('sddcmgr_url')}/v1/users/ui",
               method: 'GET',
               headers: {
                 'Accept' => 'application/json',
                 'Authorization' => "Bearer #{input('sddcmgr_sessionToken')}"
               },
               ssl_verify: false)

  describe roles do
    its('status') { should cmp 200 }
  end
  describe users do
    its('status') { should cmp 200 }
  end
  unless roles.status != 200 || users.status != 200
    usersjson = JSON.parse(users.body)
    rolesjson = JSON.parse(roles.body)
    if !usersjson.blank?
      usersjson['elements'].each do |user|
        # Get username and role id for current user
        username = user['name'].downcase
        userroleid = user['role']['id']
        currentrole = rolesjson['elements'].find { |x| x['id'] == userroleid }
        rolename = currentrole['description']
        authorizeduser = sddcmgr_authorizedPermissions.find { |x| x['user'] == username }
        authorizedusers = sddcmgr_authorizedPermissions.map { |x| x.slice('user')['user'] }

        if authorizeduser
          describe "Validating role: #{rolename} assigned to User: #{username}" do
            subject { rolename }
            it { should cmp authorizeduser['role'] }
          end
        else
          describe "Unknown User: #{username} found with assigned Role: #{rolename}" do
            subject { username }
            it { should be_in authorizedusers }
          end
        end
      end
    else
      describe 'Unable to validate assigned roles. No results returned.' do
        subject { usersjson['elements'] }
        it { should_not be_blank }
      end
    end
  end
end
