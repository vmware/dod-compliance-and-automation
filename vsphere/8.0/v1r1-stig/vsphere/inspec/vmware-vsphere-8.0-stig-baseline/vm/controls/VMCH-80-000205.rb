control 'VMCH-80-000205' do
  title 'Virtual machines (VMs) must configure log size.'
  desc 'The ESXi hypervisor maintains logs for each individual VM by default. These logs contain information including but not limited to power events, system failure information, tools status and activity, time sync, virtual hardware changes, vMotion migrations, and machine clones.

By default, the size of these logs is unlimited, and they are only rotated on vMotion or power events. This can cause storage issues at scale for VMs that do not vMotion or power cycle often.'
  desc 'check', 'For each virtual machine do the following:

From the vSphere Client, right-click the Virtual Machine and go to Edit Settings >> Advanced Parameters.

Verify the "log.rotateSize" value is set to "2048000".

or

From a PowerCLI command prompt while connected to the ESXi host or vCenter server, run the following command:

Get-VM "VM Name" | Get-AdvancedSetting -Name log.rotateSize

If the virtual machine advanced setting "log.rotateSize" is not set to "2048000", this is a finding.

If the virtual machine advanced setting "log.rotateSize" does NOT exist, this is NOT a finding.'
  desc 'fix', 'For each virtual machine do the following:

From the vSphere Client, right-click the Virtual Machine and go to Edit Settings >> Advanced Parameters.

Find the "log.rotateSize" value and set it to "2048000".

If the setting does not exist no action is needed.

or

From a PowerCLI command prompt while connected to the ESXi host or vCenter server, run the following command:

Get-VM "VM Name" | Get-AdvancedSetting -Name log.rotateSize | Set-AdvancedSetting -Value 2048000

Note: The VM must be powered off to configure the advanced settings through the vSphere Client. Therefore, it is recommended to configure these settings with PowerCLI as this can be done while the VM is powered on. Settings do not take effect via either method until the virtual machine is cold started, not rebooted.'
  impact 0.5
  tag check_id: 'C-62458r933213_chk'
  tag severity: 'medium'
  tag gid: 'V-258718'
  tag rid: 'SV-258718r933215_rule'
  tag stig_id: 'VMCH-80-000205'
  tag gtitle: 'SRG-OS-000480-VMM-002000'
  tag fix_id: 'F-62367r933214_fix'
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
      command = "Get-VM -Name '#{vm}' | Get-AdvancedSetting -Name log.rotateSize | Select-Object -ExpandProperty Value"
      result = powercli_command(command).stdout.strip
      describe.one do
        describe "VM: #{vm}" do
          subject { result }
          it { should cmp '2048000' }
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
