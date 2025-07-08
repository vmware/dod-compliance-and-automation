control 'NALB-CO-000010' do
  title 'The NSX Advanced Load Balancer Controller must be configured to assign appropriate user roles.'
  desc  "
    In NSX-ALB, each user is associated with a role. The role defines the type of access the user has to each area of the NSX-ALB System.

    Roles provide granular Role-Based Access Control (RBAC) within NSX-ALB. Failure to provide logical access restrictions associated with changes to device configuration may have significant effects on the overall security of the system.

    Successful identification and authentication must not automatically give an entity full access to a network device or security domain. The lack of authorization-based access control could result in the immediate compromise and unauthorized access to sensitive information. All DoD systems must be properly configured to incorporate access control methods that do not rely solely on authentication for authorized access.

    Authorization is the process of determining whether an entity, once authenticated, is permitted to access a specific asset or set of resources. Information systems use access control policies and enforcement mechanisms to implement this requirement. Authorization procedures and controls must be implemented to ensure each authenticated entity also has a validated and current authorization.

    Some network devices are pre-configured with security groups. Other network devices enable operators to create custom security groups with custom permissions. For example, an ISSM may require read-only access to audit the network device. Operators may create an audit security group, define permissions and access levels for members of the group, and then assign the ISSM’s user persona to the audit security group. This is still considered privileged access, but the ISSM’s security group is more restrictive than the network administrator’s security group.

    Network devices that rely on AAA brokers for authentication and authorization services may need to identify the available security groups or access levels available on the network devices and convey that information to the AAA operator. Once the AAA broker identifies the user persona on the centralized directory service, the user’s security group memberships can be retrieved. The AAA operator may need to create a mapping that links target security groups from the directory service to the appropriate security groups or access levels on the network device. Once these mappings are configured, authorizations can happen dynamically, based on each user’s directory service group membership.

  "
  desc  'rationale', ''
  desc  'check', "
    Review the roles and permissions assigned to users.

    From the NSX ALB Controller web interface go to Administration >> Accounts >> Users.

    If any user is assigned a tenant and/or role that is not authorized, this is a finding.
  "
  desc 'fix', "
    To update local user roles and tenant access do the following:

    From the NSX ALB Controller web interface go to Administration >> Accounts >> Users.

    Select the target user and click edit.

    Update the users tenant and/or role and click Save.

    To update remote users update the Auth Profile policy used to import users and adjust appropriately.
  "
  impact 0.7
  tag severity: 'high'
  tag gtitle: 'SRG-APP-000033-NDM-000212'
  tag satisfies: ['SRG-APP-000329-NDM-000287', 'SRG-APP-000340-NDM-000288', 'SRG-APP-000378-NDM-000302', 'SRG-APP-000380-NDM-000304']
  tag gid: 'V-NALB-CO-000010'
  tag rid: 'SV-NALB-CO-000010'
  tag stig_id: 'NALB-CO-000010'
  tag cci: ['CCI-000213', 'CCI-001812', 'CCI-001813', 'CCI-002169', 'CCI-002235']
  tag nist: ['AC-3', 'AC-3 (7)', 'AC-6 (10)', 'CM-11 (2)', 'CM-5 (1)']

  describe 'This check is a manual or policy based check and must be reviewed manually.' do
    skip 'This check is a manual or policy based check and must be reviewed manually.'
  end
end
