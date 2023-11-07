control 'VCSA-80-000284' do
  title 'The vCenter Server must restrict access to the default roles with cryptographic permissions.'
  desc 'In vSphere, the built-in "Administrator" role contains permission to perform cryptographic operations such as Key Management Server (KMS) functions and encrypting and decrypting virtual machine disks. This role must be reserved for cryptographic administrators where virtual machine encryption and/or vSAN encryption is in use.

A new built-in role called "No Cryptography Administrator" exists to provide all administrative permissions except cryptographic operations. Permissions must be restricted such that normal vSphere administrators are assigned the "No Cryptography Administrator" role or more restrictive.

The "Administrator" role must be tightly controlled and must not be applied to administrators who will not be doing cryptographic work. Catastrophic data loss can result from poorly administered cryptography.'
  desc 'check', 'By default, there are four roles that contain cryptographic related permissions: Administrator, No Trusted Infrastructure Administrator, vCLSAdmin, and vSphere Kubernetes Manager.

From the vSphere Client, go to Administration >> Access Control >> Roles.

or

From a PowerCLI command prompt while connected to the vCenter server, run the following command:

Get-VIPermission | Where {$_.Role -eq "Admin" -or $_.Role -eq "NoTrustedAdmin" -or $_.Role -eq "vCLSAdmin" -or $_.Role -eq "vSphereKubernetesManager"} | Select Role,Principal,Entity,Propagate,IsGroup | FT -Auto

If there are any users or groups assigned to the default roles with cryptographic permissions and are not explicitly designated to perform cryptographic operations, this is a finding.

The built-in solution users assigned to the administrator role are NOT a finding.'
  desc 'fix', 'From the vSphere Client, go to Administration >> Access Control >> Roles.

Move any accounts not explicitly designated for cryptographic operations, other than Solution Users, to other roles such as "No Cryptography Administrator".'
  impact 0.5
  tag check_id: 'C-62691r934509_chk'
  tag severity: 'medium'
  tag gid: 'V-258951'
  tag rid: 'SV-258951r934511_rule'
  tag stig_id: 'VCSA-80-000284'
  tag gtitle: 'SRG-APP-000516'
  tag fix_id: 'F-62600r934510_fix'
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']

  vcCryptoAdmins = input('vcCryptoAdmins')

  # Get all users/groups with Admin/Administrator role excluding vpxd- accounts
  command = 'Get-VIPermission | Where-Object {($_.Role -eq "Admin" -or $_.Role -eq "NoTrustedAdmin" -or $_.Role -eq "vCLSAdmin" -or $_.Role -eq "vSphereKubernetesManager") -and $_.Principal -notmatch "vpxd-"} | Select-Object -ExpandProperty Principal'
  cryptoadmins = powercli_command(command).stdout.gsub("\r\n", "\n").split("\n")

  if !cryptoadmins.empty?
    cryptoadmins.each do |cryptoadmin|
      describe cryptoadmin do
        subject { cryptoadmin }
        it { should be_in vcCryptoAdmins }
      end
    end
  else
    describe 'No users/groups found assigned to crypto roles...skipping tests.' do
      skip 'No users/groups found assigned to crypto roles...skipping tests.'
    end
  end
end
