control 'ESXI-80-000219' do
  title 'The ESXi host must restrict use of the dvFilter network application programming interface (API).'
  desc 'If the organization is not using products that use the dvFilter network API, the host should not be configured to send network information to a virtual machine (VM).

If the API is enabled, an attacker might attempt to connect a virtual machine to it, potentially providing access to the network of other VMs on the host.

If using a product that makes use of this API, verify the host has been configured correctly. If not using such a product, ensure the setting is blank.'
  desc 'check', 'From the vSphere Client, go to Hosts and Clusters.

Select the ESXi Host >> Configure >> System >> Advanced System Settings.

Select the "Net.DVFilterBindIpAddress" value and verify the value is blank or the correct IP address of a security appliance if in use.

or

From a PowerCLI command prompt while connected to the ESXi host, run the following command:

Get-VMHost | Get-AdvancedSetting -Name Net.DVFilterBindIpAddress

If the "Net.DVFilterBindIpAddress" setting is not blank and security appliances are not in use on the host, this is a finding.'
  desc 'fix', 'From the vSphere Client, go to Hosts and Clusters.

Select the ESXi Host >> Configure >> System >> Advanced System Settings.

Click "Edit". Select the "Net.DVFilterBindIpAddress" value and remove any incorrect addresses.

or

From a PowerCLI command prompt while connected to the ESXi host, run the following command:

Get-VMHost | Get-AdvancedSetting -Name Net.DVFilterBindIpAddress | Set-AdvancedSetting -Value ""'
  impact 0.5
  tag check_id: 'C-62514r933381_chk'
  tag severity: 'medium'
  tag gid: 'V-258774'
  tag rid: 'SV-258774r933383_rule'
  tag stig_id: 'ESXI-80-000219'
  tag gtitle: 'SRG-OS-000480-VMM-002000'
  tag fix_id: 'F-62423r933382_fix'
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
      command = "Get-VMHost -Name #{vmhost} | Get-AdvancedSetting -Name Net.DVFilterBindIpAddress | Select-Object -ExpandProperty Value"
      describe powercli_command(command) do
        its('stdout.strip') { should cmp '' }
      end
    end
  else
    describe 'No hosts found!' do
      skip 'No hosts found...skipping tests'
    end
  end
end
