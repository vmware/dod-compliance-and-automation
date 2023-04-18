control 'VCSA-80-000298' do
  title 'The vCenter Server must separate authentication and authorization for administrators.'
  desc  "
    Many organizations do both authentication and authorization using a centralized directory service such as Active Directory. Attackers who compromise an identity source can often add themselves to authorization groups, and simply log into systems they should not otherwise have access to. Additionally, reliance on central identity systems means that the administrators of those systems are potentially infrastructure administrators, too, as they can add themselves to infrastructure access groups at will.

    The use of local SSO groups for authorization helps prevent this avenue of attack by allowing the centralized identity source to still authenticate users but moving authorization into vCenter itself.
  "
  desc  'rationale', ''
  desc  'check', "
    From the vSphere Client, go to Administration >> Access Control >> Roles.

    View the Administrator role and any other role providing administrative access to vCenter to verify the users and/or groups assigned to it by clicking on \"Usage\".

    or

    From a PowerCLI command prompt while connected to the vCenter server, run the following command:

    Get-VIPermission | Sort Role | Select Role,Principal,Entity,Propagate,IsGroup | FT -Auto

    If any user or group is directly assigned a role with administrative access to vCenter that is from an identity provider, this is a finding.

    Note: Users and/or groups assigned to roles should be from the \"VSPHERE.LOCAL\" identity source.
  "
  desc 'fix', "
    To add groups from an identity provider to the local SSO Administrators group, as an example, do the following:

    From the vSphere Client, go to Administration >> Single Sign On >> Groups.

    Select the Administrators group and click \"Edit\".

    In the \"Add Members\" section, select the identity source and type the name of the target user/group in the search bar.

    Select the target user/group to add them and click \"Save\".

    Note: A new SSO group or groups can be created as needed and used to provide authorization to vCenter.

    To remove identity provider users/groups from a role, do the following:

    From the vSphere Client, go to Administration >> Access Control >> Global Permissions.

    Select the offending user/group and click \"Delete\".

    Note: If permissions are assigned on a specific object, then the role must be updated where it is assigned (for example, at the cluster level).
  "
  impact 0.5
  tag severity: 'medium'
  tag gtitle: 'SRG-APP-000516'
  tag gid: 'V-VCSA-80-000298'
  tag rid: 'SV-VCSA-80-000298'
  tag stig_id: 'VCSA-80-000298'
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']

  describe 'This check is a manual or policy based check and must be reviewed manually.' do
    skip 'This check is a manual or policy based check and must be reviewed manually.'
  end
end
