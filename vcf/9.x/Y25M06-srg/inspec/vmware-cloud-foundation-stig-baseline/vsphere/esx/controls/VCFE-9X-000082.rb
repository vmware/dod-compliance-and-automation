control 'VCFE-9X-000082' do
  title 'The ESX host must enable Secure Boot enforcement for configuration encryption.'
  desc  "
    Starting in vSphere 7.0 Update 2, the ESX configuration is protected by encryption. When an ESX host is optionally protected by a TPM, the ESX configuration encryption key is sealed by the TPM.

    Many ESX services store secrets in their configuration files. These configurations persist in an ESX host's boot bank as an encrypted archived file. As a result, attackers cannot read or alter this file directly, even if they have physical access to the ESX host's storage. In addition to preventing an attacker from accessing secrets, a secure ESX configuration when used with a TPM can save virtual machine encryption keys across reboots. As a result, encrypted workloads can continue to function when a key server is unavailable or unreachable.

    Secure Boot is part of the UEFI firmware standard. With UEFI Secure Boot enabled, a host refuses to load any UEFI driver or app unless the operating system bootloader has a valid digital signature. Secure Boot for ESX requires support from the firmware and it requires that all ESX kernel modules, drivers and VIBs be signed by VMware or a partner subordinate.

    Secure Boot is enabled in the BIOS of the ESX physical server and supported by the hypervisor boot loader. This control flips ESX from merely supporting Secure Boot to requiring it. Without this setting enabled, and configuration encryption, an ESX host could be subject to offline attacks and an attacker could simply transfer the ESX install drive to a host without Secure Boot and boot it up.
  "
  desc  'rationale', ''
  desc  'check', "
    If the ESX host does not have a compatible TPM, this finding is downgraded to a CAT III.

    From an ESX shell, run the following command:

    # esxcli system settings encryption get

    or

    From a PowerCLI command prompt while connected to the ESX host, run the following commands:

    $esxcli = Get-EsxCli -v2
    $esxcli.system.settings.encryption.get.invoke() | Select RequireSecureBoot | Format-List

    Example result:

    Require Secure Boot: true

    If \"Require Secure Boot\" is not enabled, this is a finding.
  "
  desc 'fix', "
    This setting cannot be configured until Secure Boot is properly enabled in the server's firmware.

    From an ESX shell, run the following commands:

    # esxcli system settings encryption set --require-secure-boot=true
    # /bin/backup.sh 0

    or

    From a PowerCLI command prompt while connected to the ESX host, run the following commands:

    $esxcli = Get-EsxCli -v2
    $arguments = $esxcli.system.settings.encryption.set.CreateArgs()
    $arguments.requiresecureboot = $true
    $esxcli.system.settings.encryption.set.Invoke($arguments)

    Evacuate the host and gracefully reboot for changes to take effect.
  "
  impact 0.5
  tag severity: 'medium'
  tag gtitle: 'SRG-OS-000257-VMM-000910'
  tag satisfies: ['SRG-OS-000258-VMM-000920', 'SRG-OS-000445-VMM-001780', 'SRG-OS-000446-VMM-001790']
  tag gid: 'V-VCFE-9X-000082'
  tag rid: 'SV-VCFE-9X-000082'
  tag stig_id: 'VCFE-9X-000082'
  tag cci: ['CCI-001494', 'CCI-001495', 'CCI-002696', 'CCI-002699']
  tag nist: ['AU-9', 'SI-6 a', 'SI-6 b']

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
      command = "$vmhost = Get-VMHost -Name #{vmhost}; $esxcli = Get-EsxCli -VMHost $vmhost -V2; $esxcli.system.settings.encryption.get.invoke() | Select-Object -ExpandProperty RequireSecureBoot"
      describe powercli_command(command) do
        its('stdout.strip') { should cmp 'true' }
      end
    end
  end
end
