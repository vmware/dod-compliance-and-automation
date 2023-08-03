control 'VCSA-70-000285' do
  title 'The vCenter Server must restrict access to cryptographic permissions.'
  desc 'These permissions must be reserved for cryptographic administrators where virtual machine encryption and/or vSAN encryption is in use. Catastrophic data loss can result from poorly administered cryptography.'
  desc 'check', %q(By default, there are four roles that contain cryptographic-related permissions: Administrator, No Trusted Infrastructure Administrator, vCLSAdmin, and vSphere Kubernetes Manager.

From the vSphere Client, go to Administration >> Access Control >> Roles.

Highlight each role and click the 'Privileges" button in the right pane.

Verify that only the Administrator, No Trusted Infrastructure Administrator, vCLSAdmin, and vSphere Kubernetes Manager and any site-specific cryptographic roles have the following permissions:

Cryptographic Operations privileges
Global.Diagnostics
Host.Inventory.Add host to cluster
Host.Inventory.Add standalone host
Host.Local operations.Manage user groups

or

From a PowerCLI command prompt while connected to the vCenter server, run the following commands:

$roles = Get-VIRole
ForEach($role in $roles){
    $privileges = $role.PrivilegeList
    If($privileges -match "Crypto*" -or $privileges -match "Global.Diagnostics" -or $privileges -match "Host.Inventory.Add*" -or $privileges -match "Host.Local operations.Manage user groups"){
    Write-Host "$role has Cryptographic privileges"
    }
}

If any role other than the four default roles contain the permissions listed above and is not authorized to perform cryptographic-related operations, this is a finding.)
  desc 'fix', 'From the vSphere Client, go to Administration >> Access Control >> Roles.

Highlight the target custom role and click "Edit".

Remove the following permissions from any custom role that is not authorized to perform cryptographic-related operations:

Cryptographic Operations privileges
Global.Diagnostics
Host.Inventory.Add host to cluster
Host.Inventory.Add standalone host
Host.Local operations.Manage user groups'
  impact 0.5
  tag check_id: 'C-60040r919038_chk'
  tag severity: 'medium'
  tag gid: 'V-256365'
  tag rid: 'SV-256365r919040_rule'
  tag stig_id: 'VCSA-70-000285'
  tag gtitle: 'SRG-APP-000516'
  tag fix_id: 'F-59983r919039_fix'
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']

  describe 'This check is a manual or policy based check' do
    skip 'This must be reviewed manually'
  end
end
