control 'VCSA-80-000285' do
  title 'The vCenter Server must restrict access to cryptographic permissions.'
  desc  'These permissions must be reserved for cryptographic administrators where virtual machine encryption and/or vSAN encryption is in use. Catastrophic data loss can result from poorly administered cryptography.'
  desc  'rationale', ''
  desc  'check', "
    By default, there are four roles that contain cryptographic related permissions: Administrator, No Trusted Infrastructure Administrator, vCLSAdmin, and vSphere Kubernetes Manager.

    From the vSphere Client, go to Administration >> Access Control >> Roles.

    Highlight each role and click the 'Privileges\" button in the right pane.

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
        If($privileges -match \"Crypto*\" -or $privileges -match \"Global.Diagnostics\" -or $privileges -match \"Host.Inventory.Add*\" -or $privileges -match \"Host.Local operations.Manage user groups\"){
        Write-Host \"$role has Cryptographic privileges\"
        }
    }

    If any role other than the four default roles contain the permissions listed above and is not authorized to perform cryptographic related operations, this is a finding.
  "
  desc 'fix', "
    From the vSphere Client, go to Administration >> Access Control >> Roles.

    Highlight the target custom role and click \"Edit\".

    Remove the following permissions from any custom role that is not authorized to perform cryptographic related operations:

    Cryptographic Operations privileges
    Global.Diagnostics
    Host.Inventory.Add host to cluster
    Host.Inventory.Add standalone host
    Host.Local operations.Manage user groups
  "
  impact 0.5
  tag severity: 'medium'
  tag gtitle: 'SRG-APP-000516'
  tag gid: 'V-VCSA-80-000285'
  tag rid: 'SV-VCSA-80-000285'
  tag stig_id: 'VCSA-80-000285'
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
