control 'VCFE-9X-000091' do
  title 'The ESX host must enable Secure Boot.'
  desc  "
    Secure Boot is part of the Unified Extensible Firmware Interface (UEFI) firmware standard. With UEFI Secure Boot enabled, a host refuses to load any UEFI driver or app unless the operating system bootloader has a valid digital signature. Secure Boot for ESX requires support from the firmware and requires that all ESX kernel modules, drivers, and vSphere Installation Bundles (VIBs) be signed by VMware or a partner subordinate.

    Secure Boot is enabled in the BIOS of the ESX physical server and supported by the hypervisor boot loader. There is no ESX control to \"turn on\" Secure Boot. Requiring Secure Boot (failing to boot without it present) is accomplished in another control.
  "
  desc  'rationale', ''
  desc  'check', "
    From an ESX shell, run the following command:

    # /usr/lib/vmware/secureboot/bin/secureBoot.py -s

    or

    From a PowerCLI command prompt while connected to the ESX host, run the following command:

    ((Get-VMHost).ExtensionData.Capability).UefiSecureBoot

    If Secure Boot is not enabled, this is a finding.
  "
  desc 'fix', "
    From an ESX shell, run the following command:

    # /usr/lib/vmware/secureboot/bin/secureBoot.py -c

    If the output indicates that Secure Boot cannot be enabled, correct the discrepancies and try again.

    Once all discrepancies are resolved, the server ESX is installed on can be updated to enable Secure Boot in the firmware.

    To enable Secure Boot in the server's firmware follow the instructions for the specific manufacturer.
  "
  impact 0.5
  tag severity: 'medium'
  tag gtitle: 'SRG-OS-000278-VMM-001000'
  tag gid: 'V-VCFE-9X-000091'
  tag rid: 'SV-VCFE-9X-000091'
  tag stig_id: 'VCFE-9X-000091'
  tag cci: ['CCI-001496']
  tag nist: ['AU-9 (3)']

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
      command = "$vmhost = Get-VMHost -Name #{vmhost}; ($vmhost.extensionData.Capability).UefiSecureBoot"
      describe powercli_command(command) do
        its('stdout.strip') { should cmp 'true' }
      end
    end
  end
end
