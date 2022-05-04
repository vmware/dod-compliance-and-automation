control 'ESXI-70-000094' do
  title 'The ESXi host must require TPM-based configuration encryption.'
  desc  "
    An ESXi host's configuration consists of configuration files for each service that runs on the host. The configuration files typically reside in the /etc/ directory, but they can also reside in other namespaces. The configuration files contain run-time information about the state of the services. Over time, the default values in the configuration files might change, for example, when you change settings on the ESXi host.

    A cron job backs up the ESXi configuration files periodically, when ESXi shuts down gracefully or on demand, and creates an archived configuration file in the boot bank. When ESXi reboots, it reads the archived configuration file and recreates the state that ESXi was in when the backup was taken.

    Before vSphere 7.0 Update 2, the archived ESXi configuration file is not encrypted. In vSphere 7.0 Update 2 and later, the archived configuration file is encrypted. When the ESXi host is configured with a Trusted Platform Module (TPM), the TPM is used to \"seal\" the configuration to the host, providing a strong security guarantee and additional protection from offline attacks.

    Configuration encryption utilizes the physical TPM when it is available and supported at install or upgrade time. If the TPM was added or enabled later, the ESXi host must be told to reconfigure to use the newly available TPM. Once the TPM configuration encryption is enabled, it cannot be disabled.
  "
  desc  'rationale', ''
  desc  'check', "
    If the ESXi host does not have a compatible TPM, this finding is downgraded to a CAT III.

    # esxcli system settings encryption get|grep Mode

    or

    From a PowerCLI command prompt while connected to the ESXi host, run the following command(s):

    $esxcli = Get-EsxCli -v2
    $esxcli.system.settings.encryption.get.invoke() | Select Mode

    Expected result:

    Mode: TPM

    If the output does not match the expected result, this is a finding.
  "
  desc 'fix', "
    Ensure that the TPM 2.0 chip is enabled in the BIOS and that the ESX UI does not show any errors about a present but unavailable TPM.

    This setting cannot be configured until the TPM is properly enabled in the BIOS.

    From an ESXi shell, run the following command(s):

    # esxcli system settings encryption set --mode=TPM

    or

    From a PowerCLI command prompt while connected to the ESXi host, run the following command(s):

    $esxcli = Get-EsxCli -v2
    $arguments = $esxcli.system.settings.encryption.set.CreateArgs()
    $arguments.mode = \"TPM\"
    $esxcli.system.settings.encryption.set.Invoke($arguments)

    Evacuate the host and gracefully reboot for changes to take effect.
  "
  impact 0.5
  tag severity: 'medium'
  tag gtitle: 'SRG-OS-000480-VMM-002000'
  tag gid: nil
  tag rid: nil
  tag stig_id: 'ESXI-70-000094'
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
      command = "$vmhost = Get-VMHost -Name #{vmhost}; $esxcli = Get-EsxCli -VMHost $vmhost -V2; $esxcli.system.settings.encryption.get.invoke() | Select-Object -ExpandProperty Mode"
      describe powercli_command(command) do
        its('stdout.strip') { should cmp 'TPM' }
      end
    end
  else
    describe 'No hosts found!' do
      skip 'No hosts found...skipping tests'
    end
  end
end
