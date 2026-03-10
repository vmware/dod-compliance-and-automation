control 'VCFE-9X-000234' do
  title 'The ESX host must use sufficient entropy for cryptographic operations.'
  desc  "
    Starting in vSphere 8.0, the ESX Entropy implementation supports the FIPS 140-3 and EAL4 certifications. Kernel boot options control which entropy sources to activate on an ESX host.

    In computing, the term \"entropy\" refers to random characters and data that are collected for use in cryptography, such as generating encryption keys to secure data transmitted over a network. Entropy is required by security for generating keys and communicating securely over the network. Entropy is often collected from a variety of sources on a system.

    FIPS entropy handling is the default behavior if the following conditions are true:

    -The hardware supports RDSEED.
    -The disableHwrng VMkernel boot option is not present or is FALSE.
    -The entropySources VMkernel boot option is not present or is 0 (zero).
  "
  desc  'rationale', ''
  desc  'check', "
    From an ESX shell, run the following commands:

    # esxcli system settings kernel list -o disableHwrng
    # esxcli system settings kernel list -o entropySources

    or

    From a PowerCLI command prompt while connected to the ESX host, run the following commands:

    $esxcli = Get-EsxCli -v2
    $esxcli.system.settings.kernel.list.invoke() | Where {$_.Name -eq \"disableHwrng\" -or $_.Name -eq \"entropySources\"}

    If \"disableHwrng\" is not set to \"false\", this is a finding.
    If \"entropySources\" is not set to \"0\", this is a finding.
  "
  desc 'fix', "
    From an ESX shell, run the following commands:

    # esxcli system settings kernel set -s disableHwrng -v FALSE
    # esxcli system settings kernel set -s entropySources -v 0

    or

    From a PowerCLI command prompt while connected to the ESX host, run the following commands:

    $esxcli = Get-EsxCli -v2
    $arguments = $esxcli.system.settings.kernel.set.CreateArgs()
    $arguments.setting = \"disableHwrng\"
    $arguments.value = \"FALSE\"
    $esxcli.system.settings.kernel.set.invoke($arguments)
    $arguments.setting = \"entropySources\"
    $arguments.value = \"0\"
    $esxcli.system.settings.kernel.set.invoke($arguments)

    Reboot the ESX host after updating entropy settings.
  "
  impact 0.5
  tag severity: 'medium'
  tag gtitle: 'SRG-OS-000480-VMM-002000'
  tag gid: 'V-VCFE-9X-000234'
  tag rid: 'SV-VCFE-9X-000234'
  tag stig_id: 'VCFE-9X-000234'
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
      command = "$vmhost = Get-VMHost -Name #{vmhost}; $esxcli = Get-EsxCli -VMHost $vmhost -V2; $esxcli.system.settings.kernel.list.invoke()| Where {$_.Name -eq \"disableHwrng\"} | Select-Object -ExpandProperty Configured"
      describe powercli_command(command) do
        its('stdout.strip') { should cmp 'FALSE' }
      end
      command = "$vmhost = Get-VMHost -Name #{vmhost}; $esxcli = Get-EsxCli -VMHost $vmhost -V2; $esxcli.system.settings.kernel.list.invoke()| Where {$_.Name -eq \"entropySources\"} | Select-Object -ExpandProperty Configured"
      describe powercli_command(command) do
        its('stdout.strip') { should cmp '0' }
      end
    end
  end
end
