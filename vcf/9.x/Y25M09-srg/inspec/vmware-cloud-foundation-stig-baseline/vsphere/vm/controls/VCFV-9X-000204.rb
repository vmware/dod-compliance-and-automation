control 'VCFV-9X-000204' do
  title 'Virtual machines (VMs) must have shared salt values disabled.'
  desc  "
    When salting is enabled (Mem.ShareForceSalting=1 or 2) to share a page between two virtual machines, both salt and the content of the page must be same. A salt value is a configurable advanced option for each virtual machine. The salt values can be specified manually in the virtual machine's advanced settings with the new option \"sched.mem.pshare.salt\".

    If this option is not present in the virtual machine's advanced settings, the value of the \"vc.uuid\" option is taken as the default value. Because the \"vc.uuid\" is unique to each virtual machine, by default Transparent Page Sharing (TPS) happens only among the pages belonging to a particular virtual machine (Intra-VM).
  "
  desc  'rationale', ''
  desc  'check', "
    For each virtual machine do the following:

    From the vSphere Client, right-click the Virtual Machine and go to Edit Settings >> Advanced Parameters.

    Verify the \"sched.mem.pshare.salt\" setting does not exist.

    or

    From a PowerCLI command prompt while connected to the ESX host or vCenter server, run the following command:

    Get-VM \"VM Name\" | Get-AdvancedSetting -Name sched.mem.pshare.salt

    If the virtual machine advanced setting \"sched.mem.pshare.salt\" exists, this is a finding.
  "
  desc  'fix', "
    For each virtual machine do the following:

    From the vSphere Client, right-click the Virtual Machine and go to Edit Settings >> Advanced Parameters.

    Delete the \"sched.mem.pshare.salt\" setting.

    or

    From a PowerCLI command prompt while connected to the ESX host or vCenter server, run the following command:

    Get-VM \"VM Name\" | Get-AdvancedSetting -Name sched.mem.pshare.salt | Remove-AdvancedSetting

    Note: The VM must be powered off to configure the advanced settings through the vSphere Client. Therefore, it is recommended to configure these settings with PowerCLI as this can be done while the VM is powered on. Settings do not take effect via either method until the virtual machine is cold started, not rebooted.
  "
  impact 0.5
  tag severity: 'medium'
  tag gtitle: 'SRG-OS-000480-VMM-002000'
  tag gid: 'V-VCFV-9X-000204'
  tag rid: 'SV-VCFV-9X-000204'
  tag stig_id: 'VCFV-9X-000204'
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']

  vmName = input('vm_Name')
  vmcluster = input('vm_cluster')
  allvms = input('vm_allvms')
  vms = []
  advSettingName = 'sched.mem.pshare.salt'

  unless vmName.blank?
    vms = powercli_command("Get-VM -Name '#{vmName}' | Sort-Object Name | Select-Object -ExpandProperty Name").stdout.gsub("\r\n", "\n").split("\n")
  end
  unless vmcluster.blank?
    vms = powercli_command("Get-VM -Location (Get-Cluster -Name '#{vmcluster}') | Sort-Object Name | Select-Object -ExpandProperty Name").stdout.gsub("\r\n", "\n").split("\n")
  end
  unless allvms == false
    vms = powercli_command('Get-VM | Sort-Object Name | Select-Object -ExpandProperty Name').stdout.gsub("\r\n", "\n").split("\n")
  end

  if vms.blank?
    describe 'No virtual machines found by name or in target vCenter...skipping test. Troubleshoot issue and rerun scan.' do
      skip 'No virtual machines found by name or in target vCenter...skipping test. Troubleshoot issue and rerun scan.'
    end
  else
    vms.each do |vm|
      command = "Get-VM -Name '#{vm}' | Get-AdvancedSetting -Name #{advSettingName} | Select-Object Name,Value,Entity | ConvertTo-Json -Depth 0 -WarningAction SilentlyContinue"
      result = powercli_command(command).stdout.strip

      describe "The setting: #{advSettingName} on VM: #{vm}" do
        subject { json(content: result) }
        its(['Value']) { should be_blank }
      end
    end
  end
end
