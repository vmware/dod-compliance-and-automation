control 'VCFV-9X-000201' do
  title 'Virtual machines (VMs) must limit informational messages from the virtual machine to the VMX file.'
  desc  "
    The configuration file containing these name-value pairs is limited to a size of 1MB. If not limited, VMware tools in the guest operating system are capable of sending a large and continuous data stream to the host. This 1MB capacity should be sufficient for most cases, but this value can change if necessary.

    The value can be increased if large amounts of custom information are being stored in the configuration file. The default limit is 1MB.
  "
  desc  'rationale', ''
  desc  'check', "
    For each virtual machine do the following:

    From the vSphere Client, right-click the Virtual Machine and go to Edit Settings >> Advanced Parameters.

    Verify the \"tools.setinfo.sizeLimit\" value is set to \"1048576\".

    or

    From a PowerCLI command prompt while connected to the ESX host or vCenter server, run the following command:

    Get-VM \"VM Name\" | Get-AdvancedSetting -Name tools.setinfo.sizeLimit

    If the virtual machine advanced setting \"tools.setinfo.sizeLimit\" is not set to \"1048576\", this is a finding.

    If the virtual machine advanced setting \"tools.setinfo.sizeLimit\" does not exist, this is not a finding.
  "
  desc  'fix', "
    For each virtual machine do the following:

    From the vSphere Client, right-click the Virtual Machine and go to Edit Settings >> Advanced Parameters.

    Find the \"tools.setinfo.sizeLimit\" value and set it to \"1048576\".

    If the setting does not exist no action is needed.

    or

    From a PowerCLI command prompt while connected to the ESX host or vCenter server, run the following command:

    Get-VM \"VM Name\" | Get-AdvancedSetting -Name tools.setinfo.sizeLimit | Set-AdvancedSetting -Value 1048576

    Note: The VM must be powered off to configure the advanced settings through the vSphere Client. Therefore, it is recommended to configure these settings with PowerCLI as this can be done while the VM is powered on. Settings do not take effect via either method until the virtual machine is cold started, not rebooted.
  "
  impact 0.5
  tag severity: 'medium'
  tag gtitle: 'SRG-OS-000480-VMM-002000'
  tag gid: 'V-VCFV-9X-000201'
  tag rid: 'SV-VCFV-9X-000201'
  tag stig_id: 'VCFV-9X-000201'
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']

  vmName = input('vm_Name')
  vmcluster = input('vm_cluster')
  allvms = input('vm_allvms')
  vms = []
  advSettingName = 'tools.setinfo.sizeLimit'

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
        its(['Value']) { should cmp('1048576').or be_blank }
      end
    end
  end
end
