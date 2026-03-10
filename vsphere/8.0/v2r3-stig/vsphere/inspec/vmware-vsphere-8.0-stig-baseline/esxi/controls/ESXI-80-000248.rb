control 'ESXI-80-000248' do
  title 'The ESXi host must disable key persistence.'
  desc 'When using a standard key provider, the ESXi host relies on vCenter Server to manage the encryption keys. When using a trusted key provider, the ESXi host relies directly on the Trust Authority Hosts for keys, and vCenter Server is not involved.

Regardless of the type of key provider, the ESXi host obtains the keys initially and retains them in its key cache. If the ESXi host reboots, it loses its key cache. The ESXi host then requests the keys again, either from the key server (standard key provider), or the Trust Authority Hosts (trusted key provider). When the ESXi host tries to obtain keys and the key server is offline or unreachable, vTPMs, vSAN encryption, and VM encryption cannot function.

In vSphere, encrypted workloads can continue to function even when the key server is offline or unreachable. If the ESXi host has a TPM, the encryption keys are persisted in the TPM across reboots. So, even if an ESXi host reboots, the host does not need to request encryption keys. Also, encryption and decryption operations can continue when the key server is unavailable, because the keys have persisted in the TPM.

If the encryption features of vSphere are used, it is to protect the confidentiality of workloads and while key persistence protects the availability of the environment it does so at the cost of confidentiality. An organization must consider the physical security posture and key provider reliability in their environments and if the risk of physical loss of equipment outweighs the availability of the workloads.'
  desc 'check', 'If the ESXi host does not have a compatible TPM, this is not applicable.

From an ESXi shell, run the following command:

# esxcli system security keypersistence get

or

From a PowerCLI command prompt while connected to the ESXi host, run the following commands:

$esxcli = Get-EsxCli -v2
$esxcli.system.security.keypersistence.get.invoke()

If key persistence is enabled, this is a finding.'
  desc 'fix', 'From an ESXi shell, run the following command:

# esxcli system security keypersistence disable --remove-all-stored-keys

or

From a PowerCLI command prompt while connected to the ESXi host, run the following commands:

$esxcli = Get-EsxCli -v2
$arguments = $esxcli.system.security.keypersistence.disable.CreateArgs()
$arguments.removeallstoredkeys = $true
$esxcli.system.security.keypersistence.disable.invoke($arguments)'
  impact 0.5
  tag check_id: 'C-69898r1003579_chk'
  tag severity: 'medium'
  tag gid: 'V-265975'
  tag rid: 'SV-265975r1003581_rule'
  tag stig_id: 'ESXI-80-000248'
  tag gtitle: 'SRG-OS-000480-VMM-002000'
  tag fix_id: 'F-69801r1003580_fix'
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']

  vmhostName = input('vmhostName')
  cluster = input('cluster')
  allhosts = input('allesxi')
  vmhosts = []

  unless vmhostName.empty?
    vmhosts = powercli_command("Get-VMHost -Name #{vmhostName} | Sort-Object Name | Select -ExpandProperty Name").stdout.split
  end
  unless cluster.empty?
    vmhosts = powercli_command("Get-Cluster -Name '#{cluster}' | Get-VMHost | Sort-Object Name | Select -ExpandProperty Name").stdout.split
  end
  unless allhosts == false
    vmhosts = powercli_command('Get-VMHost | Sort-Object Name | Select -ExpandProperty Name').stdout.split
  end

  if !vmhosts.empty?
    vmhosts.each do |vmhost|
      command = "$vmhost = Get-VMHost -Name #{vmhost}; $esxcli = Get-EsxCli -VMHost $vmhost -V2; $esxcli.system.security.keypersistence.get.invoke() | Select-Object -ExpandProperty Enabled"
      describe powercli_command(command) do
        its('stdout.strip') { should cmp 'false' }
      end
    end
  else
    describe 'No hosts found!' do
      skip 'No hosts found...skipping tests'
    end
  end
end
