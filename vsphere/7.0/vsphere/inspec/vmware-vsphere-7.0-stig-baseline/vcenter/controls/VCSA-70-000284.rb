control 'VCSA-70-000284' do
  title 'The vCenter Server must restrict access to the default roles with cryptographic permissions.'
  desc 'In vSphere, a number of default roles contain permission to perform cryptographic operations such as Key Management Server (KMS) functions and encrypting and decrypting virtual machine disks. These roles must be reserved for cryptographic administrators where virtual machine encryption and/or vSAN encryption is in use.

A new built-in role called "No Cryptography Administrator" exists to provide all administrative permissions except cryptographic operations. Permissions must be restricted such that normal vSphere administrators are assigned the "No Cryptography Administrator" role or more restrictive.

These default roles must be tightly controlled and must not be applied to administrators who will not be doing cryptographic work. Catastrophic data loss can result from poorly administered cryptography.'
  desc 'check', 'By default, there are four roles that contain cryptographic-related permissions: Administrator, No Trusted Infrastructure Administrator, vCLSAdmin, and vSphere Kubernetes Manager.

From the vSphere Client, go to Administration >> Access Control >> Roles.

or

From a PowerCLI command prompt while connected to the vCenter server, run the following command:

Get-VIPermission | Where {$_.Role -eq "Admin" -or $_.Role -eq "NoTrustedAdmin" -or $_.Role -eq "vCLSAdmin" -or $_.Role -eq "vSphereKubernetesManager"} | Select Role,Principal,Entity,Propagate,IsGroup | FT -Auto

If there are any users or groups assigned to the default roles with cryptographic permissions and are not explicitly designated to perform cryptographic operations, this is a finding.

The built-in solution users assigned to the administrator role are NOT a finding.'
  desc 'fix', 'From the vSphere Client, go to Administration >> Access Control >> Roles.

Move any accounts not explicitly designated for cryptographic operations, other than Solution Users, to other roles such as "No Cryptography Administrator".'
  impact 0.5
  tag check_id: 'C-60039r919044_chk'
  tag severity: 'medium'
  tag gid: 'V-256364'
  tag rid: 'SV-256364r919045_rule'
  tag stig_id: 'VCSA-70-000284'
  tag gtitle: 'SRG-APP-000516'
  tag fix_id: 'F-59982r885702_fix'
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']

  describe 'This check is a manual or policy based check' do
    skip 'This must be reviewed manually'
  end
end
