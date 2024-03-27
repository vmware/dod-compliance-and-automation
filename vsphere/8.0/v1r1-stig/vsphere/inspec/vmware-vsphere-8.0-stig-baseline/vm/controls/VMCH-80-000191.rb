control 'VMCH-80-000191' do
  title 'Virtual machines (VMs) must have drag and drop operations disabled.'
  desc 'Copy and paste operations are disabled by default; however, explicitly disabling this feature will enable audit controls to verify this setting is correct. Copy, paste, drag and drop, or GUI copy/paste operations between the guest operating system and the remote console could provide the means for an attacker to compromise the VM.'
  desc 'check', 'For each virtual machine do the following:

From the vSphere Client, right-click the Virtual Machine and go to Edit Settings >> Advanced Parameters.

Verify the "isolation.tools.dnd.disable" value is set to "true".

or

From a PowerCLI command prompt while connected to the ESXi host or vCenter server, run the following command:

Get-VM "VM Name" | Get-AdvancedSetting -Name isolation.tools.dnd.disable

If the virtual machine advanced setting "isolation.tools.dnd.disable" is not set to "true", this is a finding.

If the virtual machine advanced setting "isolation.tools.dnd.disable" does not exist, this is not a finding.'
  desc 'fix', 'For each virtual machine do the following:

From the vSphere Client, right-click the Virtual Machine and go to Edit Settings >> Advanced Parameters.

Find the "isolation.tools.dnd.disable" value and set it to "true".

If the setting does not exist no action is needed.

or

From a PowerCLI command prompt while connected to the ESXi host or vCenter server, run the following command:

Get-VM "VM Name" | Get-AdvancedSetting -Name isolation.tools.dnd.disable | Set-AdvancedSetting -Value true

Note: The VM must be powered off to configure the advanced settings through the vSphere Client. Therefore, it is recommended to configure these settings with PowerCLI as this can be done while the VM is powered on. Settings do not take effect via either method until the virtual machine is cold started, not rebooted.'
  impact 0.3
  tag check_id: 'C-62444r933171_chk'
  tag severity: 'low'
  tag gid: 'V-258704'
  tag rid: 'SV-258704r933173_rule'
  tag stig_id: 'VMCH-80-000191'
  tag gtitle: 'SRG-OS-000480-VMM-002000'
  tag fix_id: 'F-62353r933172_fix'
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']

  vmName = input('vmName')
  allvms = input('allvms')
  vms = []

  unless vmName.empty?
    vms = powercli_command("Get-VM -Name '#{vmName}' | Sort-Object Name | Select -ExpandProperty Name").stdout.gsub("\r\n", "\n").split("\n")
  end
  unless allvms == false
    vms = powercli_command('Get-VM | Sort-Object Name | Select -ExpandProperty Name').stdout.gsub("\r\n", "\n").split("\n")
  end

  if !vms.empty?
    vms.each do |vm|
      command = "Get-VM -Name '#{vm}' | Get-AdvancedSetting -Name isolation.tools.dnd.disable | Select-Object -ExpandProperty Value"
      result = powercli_command(command).stdout.strip
      describe.one do
        describe "VM: #{vm}" do
          subject { result }
          it { should cmp 'true' }
        end
        describe "VM: #{vm}" do
          subject { result }
          it { should be_empty }
        end
      end
    end
  else
    describe 'No VMs found!' do
      skip 'No VMs found...skipping tests'
    end
  end
end
