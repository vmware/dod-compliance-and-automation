control 'VCFE-9X-000229' do
  title 'The ESX host must enable "execInstalledOnly" enforcement for configuration encryption.'
  desc  'The "execInstalledOnly" advanced ESX boot option, when enabled, helps protect your hosts against ransomware attacks by ensuring that the VMkernel executes only those binaries on a host that have been properly packaged and signed as part of a valid VIB. While this option is effective on its own, it can be further enhanced by telling the Secure Boot to check with the TPM to make sure that the boot process does not proceed unless this setting is enabled. This further protects against malicious offline changes to ESX configuration to disable the "execInstalledOnly" option.'
  desc  'rationale', ''
  desc  'check', "
    If the ESX host does not have a compatible TPM, this finding is downgraded to a CAT III.

    From an ESX shell, run the following command:

    # esxcli system settings encryption get

    or

    From a PowerCLI command prompt while connected to the ESX host, run the following commands:

    $esxcli = Get-EsxCli -v2
    $esxcli.system.settings.encryption.get.invoke() | Select RequireExecutablesOnlyFromInstalledVIBs | Format-List

    Example result:

    RequireExecutablesOnlyFromInstalledVIBs : true

    If \"Require Executables Only From Installed VIBs\" is not enabled, this is a finding.
  "
  desc 'fix', "
    This setting cannot be configured until Secure Boot is properly enabled in the server's firmware.

    From an ESX shell, run the following commands:

    # esxcli system settings encryption set --require-exec-installed-only=True
    # /bin/backup.sh 0

    or

    From a PowerCLI command prompt while connected to the ESX host, run the following commands:

    $esxcli = Get-EsxCli -v2
    $arguments = $esxcli.system.settings.encryption.set.CreateArgs()
    $arguments.requireexecinstalledonly = $true
    $esxcli.system.settings.encryption.set.Invoke($arguments)

    Evacuate the host and gracefully reboot for changes to take effect.
  "
  impact 0.5
  tag severity: 'medium'
  tag gtitle: 'SRG-OS-000480-VMM-002000'
  tag gid: 'V-VCFE-9X-000229'
  tag rid: 'SV-VCFE-9X-000229'
  tag stig_id: 'VCFE-9X-000229'
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
      command = "$vmhost = Get-VMHost -Name #{vmhost}; $esxcli = Get-EsxCli -VMHost $vmhost -V2; $esxcli.system.settings.encryption.get.invoke() | Select-Object -ExpandProperty RequireExecutablesOnlyFromInstalledVIBs"
      describe powercli_command(command) do
        its('stdout.strip') { should cmp 'true' }
      end
    end
  end
end
