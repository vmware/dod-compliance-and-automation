control 'VCFE-9X-000236' do
  title 'The ESX host must disable key persistence.'
  desc  "
    When using a standard key provider, the ESX host relies on vCenter Server to manage the encryption keys. When using a trusted key provider, the ESX host relies directly on the Trust Authority Hosts for keys, and vCenter Server is not involved.

    Regardless of the type of key provider, the ESX host obtains the keys initially and retains them in its key cache. If the ESX host reboots, it loses its key cache. The ESX host then requests the keys again, either from the key server (standard key provider), or the Trust Authority Hosts (trusted key provider). When the ESX host tries to obtain keys and the key server is offline or unreachable, vTPMs, vSAN encryption, and VM encryption cannot function.

    In vSphere, encrypted workloads can continue to function even when the key server is offline or unreachable. If the ESX host has a TPM, the encryption keys are persisted in the TPM across reboots. So, even if an ESX host reboots, the host does not need to request encryption keys. Also, encryption and decryption operations can continue when the key server is unavailable, because the keys have persisted in the TPM.

    If the encryption features of vSphere are used, it is to protect the confidentiality of workloads and while key persistence protects the availability of the environment it does so at the cost of confidentiality. An organization must consider the physical security posture and key provider reliability in their environments and if the risk of physical loss of equipment outweighs the availability of the workloads.
  "
  desc  'rationale', ''
  desc  'check', "
    If the ESX host does not have a compatible TPM, this is not applicable.

    From an ESX shell, run the following command:

    # esxcli system security keypersistence get

    or

    From a PowerCLI command prompt while connected to the ESX host, run the following commands:

    $esxcli = Get-EsxCli -v2
    $esxcli.system.security.keypersistence.get.invoke()

    If key persistence is enabled, this is a finding.
  "
  desc 'fix', "
    From an ESX shell, run the following command:

    # esxcli system security keypersistence disable --remove-all-stored-keys

    or

    From a PowerCLI command prompt while connected to the ESX host, run the following commands:

    $esxcli = Get-EsxCli -v2
    $arguments = $esxcli.system.security.keypersistence.disable.CreateArgs()
    $arguments.removeallstoredkeys = $true
    $esxcli.system.security.keypersistence.disable.invoke($arguments)
  "
  impact 0.5
  tag severity: 'medium'
  tag gtitle: 'SRG-OS-000480-VMM-002000'
  tag gid: 'V-VCFE-9X-000236'
  tag rid: 'SV-VCFE-9X-000236'
  tag stig_id: 'VCFE-9X-000236'
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']

  vmhostName = input('esx_vmhostName')
  cluster = input('esx_cluster')
  allhosts = input('esx_allHosts')
  vmhosts = []

  unless vmhostName.blank?
    vmhosts = powercli_command("Get-VMHost -Name #{vmhostName} | Sort-Object Name | Select -ExpandProperty Name").stdout.gsub("\r\n", "\n").split("\n")
  end
  unless cluster.blank?
    vmhosts = powercli_command("Get-Cluster -Name '#{cluster}' | Get-VMHost | Sort-Object Name | Select -ExpandProperty Name").stdout.gsub("\r\n", "\n").split("\n")
  end
  unless allhosts == false
    vmhosts = powercli_command('Get-VMHost | Sort-Object Name | Select -ExpandProperty Name').stdout.gsub("\r\n", "\n").split("\n")
  end

  if vmhosts.blank?
    describe 'No ESX hosts found by name or in target vCenter...skipping test. Troubleshoot issue and rerun scan.' do
      skip 'No ESX hosts found by name or in target vCenter...skipping test. Troubleshoot issue and rerun scan.'
    end
  else
    vmhosts.each do |vmhost|
      command = "$vmhost = Get-VMHost -Name #{vmhost}; $esxcli = Get-EsxCli -VMHost $vmhost -V2; $esxcli.system.security.keypersistence.get.invoke() | Select-Object -ExpandProperty Enabled"
      describe powercli_command(command) do
        its('stdout.strip') { should cmp 'false' }
      end
    end
  end
end
