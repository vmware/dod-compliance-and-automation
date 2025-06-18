control 'VCFE-9X-000228' do
  title 'The ESX host must only run binaries from signed VIBs.'
  desc  'The "execInstalledOnly" advanced ESX boot option, when enabled, helps protect your hosts against ransomware attacks by ensuring that the VMkernel executes only those binaries on a host that have been properly packaged and signed as part of a valid VIB.'
  desc  'rationale', ''
  desc  'check', "
     From the vSphere Client, go to Hosts and Clusters.

     Select the ESX Host >> Configure >> System >> Advanced System Settings.

     Select the \"VMkernel.Boot.execInstalledOnly\" value and verify that it is \"true\".

     or

     From a PowerCLI command prompt while connected to the ESX host, run the following command:

     Get-VMHost | Get-AdvancedSetting -Name VMkernel.Boot.execInstalledOnly

     If the \"VMkernel.Boot.execInstalledOnly\" setting is not \"true\", this is a finding.
  "
  desc 'fix', "
    From the vSphere Client, go to Hosts and Clusters.

     Select the ESX Host >> Configure >> System >> Advanced System Settings.

     Click \"Edit\". Select the \"VMkernel.Boot.execInstalledOnly\" value and configure it to \"true\".

     or

     From a PowerCLI command prompt while connected to the ESX host, run the following command:

     Get-VMHost | Get-AdvancedSetting -Name VMkernel.Boot.execInstalledOnly | Set-AdvancedSetting -Value True

    Note: A reboot of the host is required to complete the process.
  "
  impact 0.5
  tag severity: 'medium'
  tag gtitle: 'SRG-OS-000480-VMM-002000'
  tag gid: 'V-VCFE-9X-000228'
  tag rid: 'SV-VCFE-9X-000228'
  tag stig_id: 'VCFE-9X-000228'
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
      command = "Get-VMHost -Name #{vmhost} | Get-AdvancedSetting -Name VMkernel.Boot.execInstalledOnly | Select-Object -ExpandProperty Value"
      describe powercli_command(command) do
        its('stdout.strip') { should cmp 'true' }
      end
    end
  end
end
