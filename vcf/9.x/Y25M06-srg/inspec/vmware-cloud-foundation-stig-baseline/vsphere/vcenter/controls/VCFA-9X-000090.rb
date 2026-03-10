control 'VCFA-9X-000090' do
  title 'VMware Cloud Foundation vCenter Server assigned roles and permissions must be verified.'
  desc  'Users and service accounts must only be assigned privileges they require. Least privilege requires that these privileges must only be assigned if needed to reduce risk of confidentiality, availability, or integrity loss.'
  desc  'rationale', ''
  desc  'check', "
    From the vSphere Client, go to Administration >> Access Control >> Roles.

    View each role and verify the users and/or groups assigned to it by clicking on \"Usage\".

    or

    From a PowerCLI command prompt while connected to the vCenter server, run the following command:

    Get-VIPermission | Select-Object Principal,Role,Entity,Propagate,IsGroup | Sort-Object Principal | FT -Auto

    Application service account and user required privileges should be documented.

    If any user or service account has more privileges than required, this is a finding.
  "
  desc 'fix', "
    To update a user's or group's permissions to an existing role with reduced permissions, do the following:

    From the vSphere Client, go to Administration >> Access Control >> Global Permissions.

    Select the user or group, click the pencil button, change the assigned role, and click \"OK\".

    Note: If permissions are assigned on a specific object, the role must be updated where it is assigned (for example, at the cluster level).

    To create a new role with reduced permissions, do the following:

    From the vSphere Client, go to Administration >> Access Control >> Roles.

    Click the green plus sign and enter a name for the role and select only the specific permissions required.

    Users can then be assigned to the newly created role.
  "
  impact 0.5
  tag severity: 'medium'
  tag gtitle: 'SRG-APP-000211'
  tag satisfies: ['SRG-APP-000384']
  tag gid: 'V-VCFA-9X-000090'
  tag rid: 'SV-VCFA-9X-000090'
  tag stig_id: 'VCFA-9X-000090'
  tag cci: ['CCI-001082', 'CCI-001764']
  tag nist: ['CM-7 (2)', 'SC-2']

  describe 'This check is either manual due to no available API or is policy based and must be reviewed manually.' do
    skip 'This check is either manual due to no available API or is policy based and must be reviewed manually.'
  end
end
