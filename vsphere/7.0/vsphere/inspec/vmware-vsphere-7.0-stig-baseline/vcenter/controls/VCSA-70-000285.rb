control 'VCSA-70-000285' do
  title 'The vCenter Server must restrict access to cryptographic permissions.'
  desc  'These permissions must be reserved for cryptographic administrators where VM encryption and/or vSAN encryption is in use. Catastrophic data loss can result from poorly administered cryptography.'
  desc  'rationale', ''
  desc  'check', "
    From the vSphere Client, go to Administration >> Access Control >> Roles.

    Highlight each role and click the 'Privileges\" button in the right pane.

    Verify that only the Administrator and any site-specific cryptographic group(s) have the following permissions:

    Cryptographic Operations privileges
    Global.Diagnostics
    Host.Inventory.Add host to cluster
    Host.Inventory.Add standalone host
    Host.Local operations.Manage user groups

    or

    From a PowerCLI command prompt while connected to the vCenter server, run the following command(s):

    $roles = Get-VIRole
    ForEach($role in $roles){
        $privileges = $role.PrivilegeList
        If($privileges -match \"Crypto*\" -or $privileges -match \"Global.Diagnostics\" -or $privileges -match \"Host.Inventory.Add*\" -or $privileges -match \"Host.Local operations.Manage user groups\"){
        Write-Host \"$role has Cryptographic privileges\"
        }
    }

    If any role other than Administrator and any site-specific group(s) have any of these permissions, this is a finding.
  "
  desc 'fix', "
    From the vSphere Client, go to Administration >> Access Control >> Roles.

    Highlight each role and click the pencil button if it is enabled.

    Remove the following permissions from any group other than Administrator and any site-specific cryptographic group(s):

    Cryptographic Operations privileges
    Global.Diagnostics
    Host.Inventory.Add host to cluster
    Host.Inventory.Add standalone host
    Host.Local operations.Manage user groups
  "
  impact 0.5
  tag severity: 'medium'
  tag gtitle: 'SRG-APP-000516'
  tag gid: nil
  tag rid: nil
  tag stig_id: 'VCSA-70-000285'
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']

  describe 'This check is a manual or policy based check' do
    skip 'This must be reviewed manually'
  end
end
