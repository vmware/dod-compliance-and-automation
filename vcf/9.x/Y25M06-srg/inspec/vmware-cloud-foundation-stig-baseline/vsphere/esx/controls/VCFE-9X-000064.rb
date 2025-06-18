control 'VCFE-9X-000064' do
  title 'The ESX host must disable Inter-Virtual Machine (VM) Transparent Page Sharing.'
  desc  "
    Transparent Page Sharing (TPS) is a method to reduce the memory footprint of virtual machines. Published academic papers have demonstrated that by forcing a flush and reload of cache memory, it is possible to measure memory timings to try to determine an Advanced Encryption Standard (AES) encryption key in use on another virtual machine running on the same physical processor of the host server if TPS is enabled between the two VMs. This technique works only under highly controlled conditions that can then be used to gain unauthorized access to data on neighboring virtual machines. VMware believes this would not be recreated in a production environment.

    Although VMware believes information being disclosed in real-world conditions is unrealistic, out of an abundance of caution, ESX will no longer enable TPS between VMs by default (TPS will still be used within individual VMs) and should be audited to ensure the default remains in place.

    The TPS behavior is controlled by the \"Mem.ShareForceSalting\" setting on ESX and the \"sched.mem.pshare.salt\" setting on VMs.
  "
  desc  'rationale', ''
  desc  'check', "
    From the vSphere Client, go to Hosts and Clusters.

    Select the ESX Host >> Configure >> System >> Advanced System Settings.

    Select the \"Mem.ShareForceSalting\" value and verify it is set to \"2\".

    or

    From a PowerCLI command prompt while connected to the ESX host, run the following command:

    Get-VMHost | Get-AdvancedSetting -Name Mem.ShareForceSalting

    If the \"Mem.ShareForceSalting\" setting is not set to 2, this is a finding.
  "
  desc 'fix', "
    From the vSphere Client, go to Hosts and Clusters.

    Select the ESX Host >> Configure >> System >> Advanced System Settings.

    Click \"Edit\". Select the \"Mem.ShareForceSalting\" value and set it to \"2\".

    or

    From a PowerCLI command prompt while connected to the ESX host, run the following command:

    Get-VMHost | Get-AdvancedSetting -Name Mem.ShareForceSalting | Set-AdvancedSetting -Value 2
  "
  impact 0.5
  tag severity: 'medium'
  tag gtitle: 'SRG-OS-000138-VMM-000670'
  tag gid: 'V-VCFE-9X-000064'
  tag rid: 'SV-VCFE-9X-000064'
  tag stig_id: 'VCFE-9X-000064'
  tag cci: ['CCI-001090']
  tag nist: ['SC-4']

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
      command = "Get-VMHost -Name #{vmhost} | Get-AdvancedSetting -Name Mem.ShareForceSalting | Select-Object -ExpandProperty Value"
      describe powercli_command(command) do
        its('stdout.strip') { should cmp '2' }
      end
    end
  end
end
