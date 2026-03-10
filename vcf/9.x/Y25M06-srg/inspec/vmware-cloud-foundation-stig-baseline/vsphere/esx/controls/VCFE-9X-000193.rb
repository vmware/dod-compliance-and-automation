control 'VCFE-9X-000193' do
  title 'The ESX host must require TPM-based configuration encryption.'
  desc  "
    An ESX host's configuration consists of configuration files for each service that runs on the host. The configuration files typically reside in the /etc/ directory, but they can also reside in other namespaces. The configuration files contain run-time information about the state of the services. Over time, the default values in the configuration files might change, for example, when settings on the ESX host are changed.

    A cron job backs up the ESX configuration files periodically, when ESX shuts down gracefully or on demand, and creates an archived configuration file in the boot bank. When ESX reboots, it reads the archived configuration file and recreates the state that ESX was in when the backup was taken.

    Before vSphere 7.0 Update 2, the archived ESX configuration file is not encrypted. In vSphere 7.0 Update 2 and later, the archived configuration file is encrypted. When the ESX host is configured with a Trusted Platform Module (TPM), the TPM is used to \"seal\" the configuration to the host, providing a strong security guarantee and additional protection from offline attacks.

    Configuration encryption uses the physical TPM when it is available and supported at install or upgrade time. If the TPM was added or enabled later, the ESX host must be told to reconfigure to use the newly available TPM. Once the TPM configuration encryption is enabled, it cannot be disabled.
  "
  desc  'rationale', ''
  desc  'check', "
    If the ESX host does not have a compatible TPM, this finding is downgraded to a CAT III.

    From an ESX shell, run the following command:

    # esxcli system settings encryption get

    or

    From a PowerCLI command prompt while connected to the ESX host, run the following commands:

    $esxcli = Get-EsxCli -v2
    $esxcli.system.settings.encryption.get.invoke() | Select Mode

    Expected result:

    Mode: TPM

    If the \"Mode\" is not set to \"TPM\", this is a finding.
  "
  desc 'fix', "
    Ensure the TPM 2.0 chip is enabled in the BIOS and the ESX UI does not show any errors about a present but unavailable TPM.

    This setting cannot be configured until the TPM is properly enabled in firmware.

    From an ESX shell, run the following command:

    # esxcli system settings encryption set --mode=TPM

    or

    From a PowerCLI command prompt while connected to the ESX host, run the following commands:

    $esxcli = Get-EsxCli -v2
    $arguments = $esxcli.system.settings.encryption.set.CreateArgs()
    $arguments.mode = \"TPM\"
    $esxcli.system.settings.encryption.set.Invoke($arguments)

    Enter the host into maintenance mode and reboot for changes to take effect.
  "
  impact 0.5
  tag severity: 'medium'
  tag gtitle: 'SRG-OS-000780-VMM-000240'
  tag gid: 'V-VCFE-9X-000193'
  tag rid: 'SV-VCFE-9X-000193'
  tag stig_id: 'VCFE-9X-000193'
  tag cci: ['CCI-004910']
  tag nist: ['SC-28 (3)']

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
      command = "$vmhost = Get-VMHost -Name #{vmhost}; $esxcli = Get-EsxCli -VMHost $vmhost -V2; $esxcli.system.settings.encryption.get.invoke() | Select-Object -ExpandProperty Mode"
      describe powercli_command(command) do
        its('stdout.strip') { should cmp 'TPM' }
      end
    end
  end
end
