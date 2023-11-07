control 'ESXI-80-000085' do
  title 'The ESXi host must implement Secure Boot enforcement.'
  desc 'Secure Boot is part of the UEFI firmware standard. With UEFI Secure Boot enabled, a host refuses to load any UEFI driver or app unless the operating system bootloader has a valid digital signature. Secure Boot for ESXi requires support from the firmware and it requires that all ESXi kernel modules, drivers, and VIBs be signed by VMware or a partner subordinate.

Secure Boot is enabled in the BIOS of the ESXi physical server and supported by the hypervisor boot loader. This control flips ESXi from merely supporting Secure Boot to requiring it. Without this setting enabled, and configuration encryption, an ESXi host could be subject to offline attacks. An attacker could simply transfer the ESXi install drive to a non-Secure Boot host and boot it up without ESXi complaining.'
  desc 'check', 'If the ESXi host does not have a compatible TPM, this finding is downgraded to a CAT III.

From an ESXi shell, run the following command:

# esxcli system settings encryption get

or

From a PowerCLI command prompt while connected to the ESXi host, run the following commands:

$esxcli = Get-EsxCli -v2
$esxcli.system.settings.encryption.get.invoke() | Select RequireSecureBoot

Expected result:

Require Secure Boot: true

If "Require Secure Boot" is not enable, this is a finding.'
  desc 'fix', 'This setting cannot be configured until Secure Boot is properly enabled in the servers firmware.

From an ESXi shell, run the following commands:

# esxcli system settings encryption set --require-secure-boot=true
# /sbin/auto-backup.sh

or

From a PowerCLI command prompt while connected to the ESXi host, run the following commands:

$esxcli = Get-EsxCli -v2
$arguments = $esxcli.system.settings.encryption.set.CreateArgs()
$arguments.requiresecureboot = $true
$esxcli.system.settings.encryption.set.Invoke($arguments)

Evacuate the host and gracefully reboot for changes to take effect.'
  impact 0.5
  tag check_id: 'C-62480r933279_chk'
  tag severity: 'medium'
  tag gid: 'V-258740'
  tag rid: 'SV-258740r933281_rule'
  tag stig_id: 'ESXI-80-000085'
  tag gtitle: 'SRG-OS-000257-VMM-000910'
  tag fix_id: 'F-62389r933280_fix'
  tag satisfies: ['SRG-OS-000257-VMM-000910', 'SRG-OS-000258-VMM-000920', 'SRG-OS-000445-VMM-001780', 'SRG-OS-000446-VMM-001790']
  tag cci: ['CCI-001494', 'CCI-001495', 'CCI-002696', 'CCI-002699']
  tag nist: ['AU-9', 'AU-9', 'SI-6 a', 'SI-6 b']

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
      command = "$vmhost = Get-VMHost -Name #{vmhost}; $esxcli = Get-EsxCli -VMHost $vmhost -V2; $esxcli.system.settings.encryption.get.invoke() | Select-Object -ExpandProperty RequireSecureBoot"
      describe powercli_command(command) do
        its('stdout.strip') { should cmp 'true' }
      end
    end
  else
    describe 'No hosts found!' do
      skip 'No hosts found...skipping tests'
    end
  end
end
