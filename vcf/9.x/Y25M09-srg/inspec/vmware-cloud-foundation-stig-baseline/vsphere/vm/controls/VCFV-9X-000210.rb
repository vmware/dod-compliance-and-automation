control 'VCFV-9X-000210' do
  title 'Virtual machines (VMs) must configure log size.'
  desc  "
    The ESX hypervisor maintains logs for each individual VM by default. These logs contain information including but not limited to power events, system failure information, tools status and activity, time sync, virtual hardware changes, vMotion migrations, and machine clones.

    By default, the size of these logs is unlimited, and they are only rotated on vMotion or power events. This can cause storage issues at scale for VMs that do not vMotion or power cycle often.
  "
  desc  'rationale', ''
  desc  'check', "
    For each virtual machine do the following:

    From the vSphere Client, right-click the Virtual Machine and go to Edit Settings >> Advanced Parameters.

    Verify the \"log.rotateSize\" value is set to \"2048000\".

    or

    From a PowerCLI command prompt while connected to the ESX host or vCenter server, run the following command:

    Get-VM \"VM Name\" | Get-AdvancedSetting -Name log.rotateSize

    If the virtual machine advanced setting \"log.rotateSize\" is not set to \"2048000\", this is a finding.

    If the virtual machine advanced setting \"log.rotateSize\" does not exist, this is not a finding.
  "
  desc  'fix', "
    For each virtual machine do the following:

    From the vSphere Client, right-click the Virtual Machine and go to Edit Settings >> Advanced Parameters.

    Find the \"log.rotateSize\" value and set it to \"2048000\".

    If the setting does not exist no action is needed.

    or

    From a PowerCLI command prompt while connected to the ESX host or vCenter server, run the following command:

    Get-VM \"VM Name\" | Get-AdvancedSetting -Name log.rotateSize | Set-AdvancedSetting -Value 2048000

    Note: The VM must be powered off to configure the advanced settings through the vSphere Client. Therefore, it is recommended to configure these settings with PowerCLI as this can be done while the VM is powered on. Settings do not take effect via either method until the virtual machine is cold started, not rebooted.
  "
  impact 0.5
  tag severity: 'medium'
  tag gtitle: 'SRG-OS-000480-VMM-002000'
  tag gid: 'V-VCFV-9X-000210'
  tag rid: 'SV-VCFV-9X-000210'
  tag stig_id: 'VCFV-9X-000210'
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']

  vmName = input('vm_Name')
  vmcluster = input('vm_cluster')
  allvms = input('vm_allvms')
  vms = []
  advSettingName = 'log.rotateSize'

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
        its(['Value']) { should cmp('2048000').or be_blank }
      end
    end
  end
end
