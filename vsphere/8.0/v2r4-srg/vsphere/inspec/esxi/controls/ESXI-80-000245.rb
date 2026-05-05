control 'ESXI-80-000245' do
  title 'The ESXi host must use sufficient entropy for cryptographic operations.'
  desc 'Starting in vSphere 8.0, the ESXi Entropy implementation supports the FIPS 140-3 and EAL4 certifications. Kernel boot options control which entropy sources to activate on an ESXi host.

In computing, the term "entropy" refers to random characters and data that are collected for use in cryptography, such as generating encryption keys to secure data transmitted over a network. Entropy is required by security for generating keys and communicating securely over the network. Entropy is often collected from a variety of sources on a system.

FIPS entropy handling is the default behavior if the following conditions are true:

-The hardware supports RDSEED.
-The disableHwrng VMkernel boot option is not present or is FALSE.
-The entropySources VMkernel boot option is not present or is 0 (zero).'
  desc 'check', 'From an ESXi shell, run the following commands:

# esxcli system settings kernel list -o disableHwrng
# esxcli system settings kernel list -o entropySources

or

From a PowerCLI command prompt while connected to the ESXi host, run the following commands:

$esxcli = Get-EsxCli -v2
$esxcli.system.settings.kernel.list.invoke() | Where {$_.Name -eq "disableHwrng" -or $_.Name -eq "entropySources"}

If "disableHwrng" is not set to "false", this is a finding.
If "entropySources" is not set to "0", this is a finding.'
  desc 'fix', 'From an ESXi shell, run the following commands:

# esxcli system settings kernel set -s disableHwrng -v FALSE
# esxcli system settings kernel set -s entropySources -v 0

or

From a PowerCLI command prompt while connected to the ESXi host, run the following commands:

$esxcli = Get-EsxCli -v2
$arguments = $esxcli.system.settings.kernel.set.CreateArgs()
$arguments.setting = "disableHwrng"
$arguments.value = "FALSE"
$esxcli.system.settings.kernel.set.invoke($arguments)
$arguments.setting = "entropySources"
$arguments.value = "0"
$esxcli.system.settings.kernel.set.invoke($arguments)

Reboot the ESXi host after updating entropy settings.'
  impact 0.5
  tag check_id: 'C-62539r933456_chk'
  tag severity: 'medium'
  tag gid: 'V-258799'
  tag rid: 'SV-258799r959010_rule'
  tag stig_id: 'ESXI-80-000245'
  tag gtitle: 'SRG-OS-000480-VMM-002000'
  tag fix_id: 'F-62448r933457_fix'
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
      command = "$vmhost = Get-VMHost -Name #{vmhost}; $esxcli = Get-EsxCli -VMHost $vmhost -V2; $esxcli.system.settings.kernel.list.invoke()| Where {$_.Name -eq \"disableHwrng\"} | Select-Object -ExpandProperty Configured"
      describe powercli_command(command) do
        its('stdout.strip') { should cmp 'FALSE' }
      end
      command = "$vmhost = Get-VMHost -Name #{vmhost}; $esxcli = Get-EsxCli -VMHost $vmhost -V2; $esxcli.system.settings.kernel.list.invoke()| Where {$_.Name -eq \"entropySources\"} | Select-Object -ExpandProperty Configured"
      describe powercli_command(command) do
        its('stdout.strip') { should cmp '0' }
      end
    end
  else
    describe 'No hosts found!' do
      skip 'No hosts found...skipping tests'
    end
  end
end
