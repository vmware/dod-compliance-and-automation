control 'ESXI-80-000213' do
  title 'The ESXi host must disable Inter-Virtual Machine (VM) Transparent Page Sharing.'
  desc 'Published academic papers have demonstrated that by forcing a flush and reload of cache memory, it is possible to measure memory timings to try to determine an Advanced Encryption Standard (AES) encryption key in use on another virtual machine running on the same physical processor of the host server if Transparent Page Sharing (TPS) is enabled between the two VMs. This technique works only in a highly controlled system configured in a nonstandard way that VMware believes would not be recreated in a production environment.

Although VMware believes information being disclosed in real-world conditions is unrealistic, out of an abundance of caution, upcoming ESXi update releases will no longer enable TPS between VMs by default (TPS will still be used within individual VMs).'
  desc 'check', 'From the vSphere Client, go to Hosts and Clusters.

Select the ESXi Host >> Configure >> System >> Advanced System Settings.

Select the "Mem.ShareForceSalting" value and verify it is set to "2".

or

From a PowerCLI command prompt while connected to the ESXi host, run the following command:

Get-VMHost | Get-AdvancedSetting -Name Mem.ShareForceSalting

If the "Mem.ShareForceSalting" setting is not set to 2, this is a finding.'
  desc 'fix', 'From the vSphere Client, go to Hosts and Clusters.

Select the ESXi Host >> Configure >> System >> Advanced System Settings.

Click "Edit". Select the "Mem.ShareForceSalting" value and set it to "2".

or

From a PowerCLI command prompt while connected to the ESXi host, run the following command:

Get-VMHost | Get-AdvancedSetting -Name Mem.ShareForceSalting | Set-AdvancedSetting -Value 2'
  impact 0.3
  tag check_id: 'C-62508r933363_chk'
  tag severity: 'low'
  tag gid: 'V-258768'
  tag rid: 'SV-258768r933365_rule'
  tag stig_id: 'ESXI-80-000213'
  tag gtitle: 'SRG-OS-000480-VMM-002000'
  tag fix_id: 'F-62417r933364_fix'
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
      command = "Get-VMHost -Name #{vmhost} | Get-AdvancedSetting -Name Mem.ShareForceSalting | Select-Object -ExpandProperty Value"
      describe powercli_command(command) do
        its('stdout.strip') { should cmp '2' }
      end
    end
  else
    describe 'No hosts found!' do
      skip 'No hosts found...skipping tests'
    end
  end
end
