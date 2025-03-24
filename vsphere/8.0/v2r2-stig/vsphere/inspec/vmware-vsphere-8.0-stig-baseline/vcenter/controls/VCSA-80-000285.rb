control 'VCSA-80-000285' do
  title 'The vCenter Server must restrict access to cryptographic permissions.'
  desc 'These permissions must be reserved for cryptographic administrators where virtual machine encryption and/or vSAN encryption is in use. Catastrophic data loss can result from poorly administered cryptography.'
  desc 'check', 'By default, there are five roles that contain cryptographic related permissions: Administrator, No Trusted Infrastructure Administrator, vCLSAdmin, VMOperator Controller Manager, and vSphere Kubernetes Manager.

From the vSphere Client, go to Administration >> Access Control >> Roles.

Highlight each role and click the "Privileges" button in the right pane.

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

If any role other than the five default roles contain the permissions listed above and is not authorized to perform cryptographic related operations, this is a finding.'
  desc 'fix', 'From the vSphere Client, go to Administration >> Access Control >> Roles.

Highlight the target custom role and click "Edit".

Remove the following permissions from any custom role that is not authorized to perform cryptographic related operations:

Cryptographic Operations privileges
Global.Diagnostics
Host.Inventory.Add host to cluster
Host.Inventory.Add standalone host
Host.Local operations.Manage user groups'
  impact 0.5
  tag check_id: 'C-62692r1003607_chk'
  tag severity: 'medium'
  tag gid: 'V-258952'
  tag rid: 'SV-258952r1003608_rule'
  tag stig_id: 'VCSA-80-000285'
  tag gtitle: 'SRG-APP-000516'
  tag fix_id: 'F-62601r934513_fix'
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']

  vcCryptoRoles = input('vcCryptoRoles')

  command = 'Get-VIRole | Where-Object {$_.PrivilegeList -match "Crypto*" -or $_.PrivilegeList -match "Global.Diagnostics" -or $_.PrivilegeList -match "Host.Inventory.Add*" -or $_.PrivilegeList -match "Host.Local operations.Manage user groups"} | Select-Object -ExpandProperty Name'
  cryptoroles = powercli_command(command).stdout.gsub("\r\n", "\n").split("\n")

  if !cryptoroles.empty?
    cryptoroles.each do |cryptorole|
      describe cryptorole do
        subject { cryptorole }
        it { should be_in vcCryptoRoles }
      end
    end
  else
    describe 'No roles found with crypto permissions...skipping tests.' do
      skip 'No roles found with crypto permissions...skipping tests.'
    end
  end
end
