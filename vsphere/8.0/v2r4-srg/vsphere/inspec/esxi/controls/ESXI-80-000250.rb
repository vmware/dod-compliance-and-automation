control 'ESXI-80-000250' do
  title 'The ESXi host must disable virtual hardware management network interfaces.'
  desc 'Hardware management controllers often present virtual or USB NICs to the ESXi host. These can be used as backdoors and should be deactivated both in the hardware configuration and in ESXi.'
  desc 'check', 'From the vSphere Client, go to Hosts and Clusters.

Select the ESXi Host >> Configure >> System >> Advanced System Settings.

Select the "Net.BMCNetworkEnable" value and verify it is set to "0".

or

From a PowerCLI command prompt while connected to the ESXi host, run the following command:

Get-VMHost | Get-AdvancedSetting -Name Net.BMCNetworkEnable

If the "Net.BMCNetworkEnable" setting is not set to "0", this is a finding.'
  desc 'fix', 'From the vSphere Client, go to Hosts and Clusters.

Select the ESXi Host >> Configure >> System >> Advanced System Settings.

Click "Edit". Select the "Net.BMCNetworkEnable" value and configure it to "0".

or

From a PowerCLI command prompt while connected to the ESXi host, run the following command:

Get-VMHost | Get-AdvancedSetting -Name Net.BMCNetworkEnable | Set-AdvancedSetting -Value 0'
  impact 0.5
  tag check_id: 'C-69900r1003585_chk'
  tag severity: 'medium'
  tag gid: 'V-265977'
  tag rid: 'SV-265977r1003587_rule'
  tag stig_id: 'ESXI-80-000250'
  tag gtitle: 'SRG-OS-000480-VMM-002000'
  tag fix_id: 'F-69803r1003586_fix'
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
      command = "Get-VMHost -Name #{vmhost} | Get-AdvancedSetting -Name Net.BMCNetworkEnable | Select-Object -ExpandProperty Value"
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
