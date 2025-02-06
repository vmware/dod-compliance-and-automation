control 'ESXI-80-000094' do
  title 'The ESXi host must enable Secure Boot.'
  desc 'Secure Boot is part of the Unified Extensible Firmware Interface (UEFI) firmware standard. With UEFI Secure Boot enabled, a host refuses to load any UEFI driver or app unless the operating system bootloader has a valid digital signature. Secure Boot for ESXi requires support from the firmware and requires that all ESXi kernel modules, drivers, and vSphere Installation Bundles (VIBs) be signed by VMware or a partner subordinate.

Secure Boot is enabled in the BIOS of the ESXi physical server and supported by the hypervisor boot loader. There is no ESXi control to "turn on" Secure Boot. Requiring Secure Boot (failing to boot without it present) is accomplished in another control.'
  desc 'check', 'From an ESXi shell, run the following command:

# /usr/lib/vmware/secureboot/bin/secureBoot.py -s

or

From a PowerCLI command prompt while connected to the ESXi host, run the following command:

((Get-VMHost).ExtensionData.Capability).UefiSecureBoot

If Secure Boot is not enabled, this is a finding.'
  desc 'fix', "From an ESXi shell, run the following command:

# /usr/lib/vmware/secureboot/bin/secureBoot.py -c

If the output indicates that Secure Boot cannot be enabled, correct the discrepancies and try again.

Once all discrepancies are resolved, the server ESXi is installed on can be updated to enable Secure Boot in the firmware.

To enable Secure Boot in the server's firmware, follow the instructions for the specific manufacturer."
  impact 0.5
  tag check_id: 'C-62481r1003520_chk'
  tag severity: 'medium'
  tag gid: 'V-258741'
  tag rid: 'SV-258741r1003563_rule'
  tag stig_id: 'ESXI-80-000094'
  tag gtitle: 'SRG-OS-000278-VMM-001000'
  tag fix_id: 'F-62390r1003521_fix'
  tag cci: ['CCI-001496']
  tag nist: ['AU-9 (3)']

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
      command = "$vmhost = Get-VMHost -Name #{vmhost}; ($vmhost.extensionData.Capability).UefiSecureBoot"
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
