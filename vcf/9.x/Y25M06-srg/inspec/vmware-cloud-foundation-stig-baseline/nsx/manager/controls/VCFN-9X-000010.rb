control 'VCFN-9X-000010' do
  title 'The VMware Cloud Foundation NSX Manager must be configured to assign appropriate user roles or access levels to authenticated users.'
  desc  "
    Successful identification and authentication must not automatically give an entity full access to a network device or security domain. The lack of authorization-based access control could result in the immediate compromise and unauthorized access to sensitive information. All DoD systems must be properly configured to incorporate access control methods that do not rely solely on authentication for authorized access.

    Authorization is the process of determining whether an entity, once authenticated, is permitted to access a specific asset or set of resources. Information systems use access control policies and enforcement mechanisms to implement this requirement. Authorization procedures and controls must be implemented to ensure each authenticated entity also has a validated and current authorization.

    Some network devices are pre-configured with security groups. Other network devices enable operators to create custom security groups with custom permissions. For example, an ISSM may require read-only access to audit the network device. Operators may create an audit security group, define permissions and access levels for members of the group, and then assign the ISSM’s user persona to the audit security group. This is still considered privileged access, but the ISSM’s security group is more restrictive than the network administrator’s security group.

    Network devices that rely on AAA brokers for authentication and authorization services may need to identify the available security groups or access levels available on the network devices and convey that information to the AAA operator. Once the AAA broker identifies the user persona on the centralized directory service, the user’s security group memberships can be retrieved. The AAA operator may need to create a mapping that links target security groups from the directory service to the appropriate security groups or access levels on the network device. Once these mappings are configured, authorizations can happen dynamically, based on each user’s directory service group membership.
  "
  desc  'rationale', ''
  desc  'check', "
    From the NSX Manager web interface, go to System >> Settings >> User Management >> User Role Assignment.

    View each user and group and verify the role assigned to it.

    If any user/group or service account are assigned to roles with privileges that are beyond those required and authorized by the organization, this is a finding.
  "
  desc 'fix', "
    To create a new role with reduced permissions, do the following:

    From the NSX Manager web interface, go to System >> Settings >> User Management >> Roles.

    Click \"Add Role\", provide a name and the required permissions, and then click \"Save\".

    To update user or group permissions to an existing role with reduced permissions, do the following:

    From the NSX Manager web interface, go to System >> User Management >> User Role Assignment.

    Click the menu dropdown next to the target user or group and select \"Edit\".

    Remove the existing role, select the new one, and then click \"Save\".
  "
  impact 0.7
  tag severity: 'high'
  tag gtitle: 'SRG-APP-000033-NDM-000212'
  tag satisfies: ['SRG-APP-000038-NDM-000213', 'SRG-APP-000119-NDM-000236', 'SRG-APP-000120-NDM-000237', 'SRG-APP-000121-NDM-000238', 'SRG-APP-000122-NDM-000239', 'SRG-APP-000123-NDM-000240', 'SRG-APP-000133-NDM-000244', 'SRG-APP-000231-NDM-000271', 'SRG-APP-000329-NDM-000287', 'SRG-APP-000340-NDM-000288', 'SRG-APP-000378-NDM-000302', 'SRG-APP-000380-NDM-000304', 'SRG-APP-000408-NDM-000314', 'SRG-APP-000516-NDM-000335', 'SRG-APP-000795-NDM-000130']
  tag gid: 'V-VCFN-9X-000010'
  tag rid: 'SV-VCFN-9X-000010'
  tag stig_id: 'VCFN-9X-000010'
  tag cci: ['CCI-000163', 'CCI-000164', 'CCI-000213', 'CCI-000345', 'CCI-000366', 'CCI-001199', 'CCI-001368', 'CCI-001493', 'CCI-001494', 'CCI-001495', 'CCI-001499', 'CCI-001813', 'CCI-002169', 'CCI-002235', 'CCI-002883', 'CCI-003831', 'CCI-003980']
  tag nist: ['AC-3', 'AC-3 (7)', 'AC-4', 'AC-6 (10)', 'AU-9', 'AU-9 a', 'AU-9 b', 'CM-11 (2)', 'CM-5', 'CM-5 (1) (a)', 'CM-5 (6)', 'CM-6 b', 'MA-3 (4)', 'SC-28']

  userroles = input('nsx_authorizedPermissions')
  usersarray = userroles.keys.flatten

  result = http("https://#{input('nsx_managerAddress')}/policy/api/v1/aaa/role-bindings",
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
    else
      describe 'Unable to validate assigned roles. No results returned.' do
        subject { users['results'] }
        it { should_not be_empty }
      end
    end
  end
end
