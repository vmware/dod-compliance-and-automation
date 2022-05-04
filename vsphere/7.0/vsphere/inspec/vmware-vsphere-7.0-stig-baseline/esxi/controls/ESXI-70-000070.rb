control 'ESXI-70-000070' do
  title 'The ESXi host must not provide root/administrator-level access to CIM-based hardware monitoring tools or other third-party applications.'
  desc  'The CIM system provides an interface that enables hardware-level management from remote applications via a set of standard APIs. In environments that implement CIM hardware monitoring, create a limited-privilege, read-only service account for CIM and place this user in the Exception Users list. When CIM write access is required, create a new role with only the "Host.CIM.Interaction" permission and apply that role to your CIM service account.'
  desc  'rationale', ''
  desc  'check', "
    If CIM monitoring is not implemented, this is Not Applicable.

    From the Host Client, select the ESXi host, right click and go to \"Permissions\".

    Verify the CIM service account is assigned the \"Read-only\" role or a custom role as described in the discussion.

    If there is no dedicated CIM service account, this is a finding.

    If the CIM service account has more permissions than necessary, from the discussion, this is a finding.
  "
  desc 'fix', "
    If write access is required, create a new role for the CIM service account:

    From the Host Client, go to manage, then Security & Users.

    Select Roles then click \"Add role\".

    Provide a name for the new role then select Host >> Cim >> Ciminteraction and click \"Add\".

    Add a CIM service account:

    From the Host Client, go to Manage >> Security & users.

    Select \"Users\" then click \"Add user\".

    Provide a name, description, and password for the new user then click \"Add\".

    Assign the CIM service account permissions to the host with the new role:

    From the Host Client, select the ESXi host, right click and go to \"Permissions\".

    Click Add User and select the CIM service account from the drop down list and select either \"Read-only\" or the role you just created. Click \"Add User\".
  "
  impact 0.5
  tag severity: 'medium'
  tag gtitle: 'SRG-OS-000480-VMM-002000'
  tag gid: nil
  tag rid: nil
  tag stig_id: 'ESXI-70-000070'
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']

  describe 'This check is a manual or policy based check' do
    skip 'This must be reviewed manually'
  end
end
