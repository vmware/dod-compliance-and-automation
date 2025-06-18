control 'VCFE-9X-000225' do
  title 'The ESX host must enable volatile key destruction.'
  desc  "
    By default, pages allocated for virtual machines (VMs), userspace applications, and kernel threads are zeroed out at allocation time. ESX will always ensure that no nonzero pages are exposed to VMs or userspace applications. While this prevents exposing cryptographic keys from VMs or userworlds to other clients, these keys can stay present in host memory for a long time if the memory is not reused.

    The NIAP Virtualization Protection Profile and Server Virtualization Extended Package require that memory that may contain cryptographic keys be zeroed upon process exit.

    To this end, a new configuration option, MemEagerZero, can be configured to enforce zeroing out userworld and guest memory pages when a userworld process or guest exits. For kernel threads, memory spaces holding keys are zeroed out as soon as the secret is no longer needed.
  "
  desc  'rationale', ''
  desc  'check', "
    From the vSphere Client, go to Hosts and Clusters.

    Select the ESX Host >> Configure >> System >> Advanced System Settings.

    Select the \"Mem.MemEagerZero\" value and verify it is set to \"1\".

    or

    From a PowerCLI command prompt while connected to the ESX host, run the following command:

    Get-VMHost | Get-AdvancedSetting -Name Mem.MemEagerZero

    If the \"Mem.MemEagerZero\" setting is not set to \"1\", this is a finding.
  "
  desc 'fix', "
    From the vSphere Client, go to Hosts and Clusters.

    Select the ESX Host >> Configure >> System >> Advanced System Settings.

    Click \"Edit\". Select the \"Mem.MemEagerZero\" value and configure it to \"1\".

    or

    From a PowerCLI command prompt while connected to the ESX host, run the following command:

    Get-VMHost | Get-AdvancedSetting -Name Mem.MemEagerZero | Set-AdvancedSetting -Value 1
  "
  impact 0.5
  tag severity: 'medium'
  tag gtitle: 'SRG-OS-000480-VMM-002000'
  tag gid: 'V-VCFE-9X-000225'
  tag rid: 'SV-VCFE-9X-000225'
  tag stig_id: 'VCFE-9X-000225'
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
      command = "Get-VMHost -Name #{vmhost} | Get-AdvancedSetting -Name Mem.MemEagerZero | Select-Object -ExpandProperty Value"
      describe powercli_command(command) do
        its('stdout.strip') { should cmp '1' }
      end
    end
  end
end
