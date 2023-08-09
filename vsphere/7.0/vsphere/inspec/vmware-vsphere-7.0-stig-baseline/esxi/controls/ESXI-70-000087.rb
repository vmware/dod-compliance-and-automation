control 'ESXI-70-000087' do
  title 'The ESXi host must enable volatile key destruction.'
  desc 'By default, pages allocated for virtual machines (VMs), userspace applications, and kernel threads are zeroed out at allocation time. ESXi will always ensure that no nonzero pages are exposed to VMs or userspace applications. While this prevents exposing cryptographic keys from VMs or userworlds to other clients, these keys can stay present in host memory for a long time if the memory is not reused.

The NIAP Virtualization Protection Profile and Server Virtualization Extended Package require that memory that may contain cryptographic keys be zeroed upon process exit.

To this end, a new configuration option, MemEagerZero, can be configured to enforce zeroing out userworld and guest memory pages when a userworld process or guest exits. For kernel threads, memory spaces holding keys are zeroed out as soon as the secret is no longer needed.'
  desc 'check', 'From the vSphere Client, go to Hosts and Clusters.

Select the ESXi Host >> Configure >> System >> Advanced System Settings.

Select the "Mem.MemEagerZero" value and verify it is set to "1".

or

From a PowerCLI command prompt while connected to the ESXi host, run the following command:

Get-VMHost | Get-AdvancedSetting -Name Mem.MemEagerZero

If the "Mem.MemEagerZero" setting is not set to "1", this is a finding.'
  desc 'fix', 'From the vSphere Client, go to Hosts and Clusters.

Select the ESXi Host >> Configure >> System >> Advanced System Settings.

Click "Edit". Select the "Mem.MemEagerZero" value and set it to "1".

or

From a PowerCLI command prompt while connected to the ESXi host, run the following command:

Get-VMHost | Get-AdvancedSetting -Name Mem.MemEagerZero | Set-AdvancedSetting -Value "1"'
  impact 0.5
  tag check_id: 'C-60114r886096_chk'
  tag severity: 'medium'
  tag gid: 'V-256439'
  tag rid: 'SV-256439r919028_rule'
  tag stig_id: 'ESXI-70-000087'
  tag gtitle: 'SRG-OS-000480-VMM-002000'
  tag fix_id: 'F-60057r919027_fix'
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
      command = "Get-VMHost -Name #{vmhost} | Get-AdvancedSetting -Name Mem.MemEagerZero | Select-Object -ExpandProperty Value"
      describe powercli_command(command) do
        its('stdout.strip') { should cmp '1' }
      end
    end
  else
    describe 'No hosts found!' do
      skip 'No hosts found...skipping tests'
    end
  end
end
