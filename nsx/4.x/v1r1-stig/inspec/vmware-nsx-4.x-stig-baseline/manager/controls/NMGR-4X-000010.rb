control 'NMGR-4X-000010' do
  title 'The NSX Manager must assign users/accounts to organization-defined roles configured with approved authorizations.'
  desc 'The lack of authorization-based access control could result in the immediate compromise and unauthorized access to sensitive information. Users must be assigned to roles which are configured with approved authorizations and access permissions. The NSX Manager must be configured granularly based on organization requirements to only allow authorized administrators to execute privileged functions. Role assignments should control which administrators can view or change the device configuration, system files, and locally stored audit information.'
  desc 'check', "From the NSX Manager web interface, go to System >> Settings >> User Management >> User Role Assignment.

View each user and group and verify the role assigned has authorization limits as appropriate to the role and in accordance with the site's documentation.

If any user/group or service account are assigned to roles with privileges that are beyond those required and authorized by the organization, this is a finding."
  desc 'fix', '
    To create a new role with reduced permissions, do the following:

    From the NSX Manager web interface, go to System >> Settings >> User Management >> Roles.

    Click "Add Role", provide a name and the required permissions, and then click "Save".

    To update user or group permissions to an existing role with reduced permissions, do the following:

    From the NSX Manager web interface, go to System >> User Management >> User Role Assignment.

    Click the menu dropdown next to the target user or group and select "Edit".

    Remove the existing role, select the new one, and then click "Save".
  '
  impact 0.7
  tag severity: 'high'
  tag gtitle: 'SRG-APP-000033-NDM-000212'
  tag satisfies: ['SRG-APP-000038-NDM-000213', 'SRG-APP-000119-NDM-000236', 'SRG-APP-000120-NDM-000237', 'SRG-APP-000133-NDM-000244', 'SRG-APP-000231-NDM-000271', 'SRG-APP-000329-NDM-000287', 'SRG-APP-000340-NDM-000288', 'SRG-APP-000378-NDM-000302', 'SRG-APP-000380-NDM-000304', 'SRG-APP-000408-NDM-000314', 'SRG-APP-000516-NDM-000335']
  tag gid: 'V-263203'
  tag rid: 'SV-263203r977376_rule'
  tag stig_id: 'NMGR-4X-000010'
  tag cci: ['CCI-000163', 'CCI-000164', 'CCI-000213', 'CCI-000345', 'CCI-001199', 'CCI-001368', 'CCI-001499', 'CCI-001812', 'CCI-001813', 'CCI-002169', 'CCI-002235', 'CCI-002883']
  tag nist: ['AC-3', 'AC-3 (7)', 'AC-4', 'AC-6 (10)', 'AU-9', 'CM-11 (2)', 'CM-5', 'CM-5 (1)', 'CM-5 (6)', 'MA-3 (4)', 'SC-28', 'AU-9 a', 'CM-5 (1) (a)']

  userroles = input('authorizedPermissions')
  usersarray = userroles.keys.flatten

  result = http("https://#{input('nsxManager')}/policy/api/v1/aaa/role-bindings",
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
      user['roles'].each do |role|
        if userroles.include?("#{user['name']}")
          expectedRole = userroles["#{user['name']}"]['role']
          describe "Validating role: #{role['role_display_name']} assigned to User: #{user['name']}" do
            subject { json(content: role.to_json)['role_display_name'] }
            it { should cmp expectedRole }
          end
        else
          describe "Unknown User: #{user['name']} found with assigned Role: #{role['role_display_name']}" do
            subject { user['name'] }
            it { should be_in usersarray }
          end
        end
      end
    end
  end
end
