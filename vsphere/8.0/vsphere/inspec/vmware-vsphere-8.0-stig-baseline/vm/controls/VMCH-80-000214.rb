control 'VMCH-80-000214' do
  title 'Virtual machines (VMs) must disable DirectPath I/O devices when not required.'
  desc 'VMDirectPath I/O (PCI passthrough) enables direct assignment of hardware PCI functions to VMs. This gives the VM access to the PCI functions with minimal intervention from the ESXi host. This is a powerful feature for legitimate applications such as virtualized storage appliances, backup appliances, dedicated graphics, etc., but it also allows a potential attacker highly privileged access to underlying hardware and the PCI bus.'
  desc 'check', 'For each virtual machine do the following:

From the vSphere Client, view the Summary tab.

Review the PCI devices section and verify none exist.

or

From a PowerCLI command prompt while connected to the ESXi host or vCenter server, run the following command:

Get-VM "VM Name" | Get-PassthroughDevice

If the virtual machine has passthrough devices present, and the specific device returned is not approved, this is a finding.'
  desc 'fix', 'From the vSphere Client, select the Virtual Machine, right-click and go to Edit Settings >> Virtual Hardware tab.

Find the unexpected PCI device returned from the check.

Hover the mouse over the device and click the circled "X" to remove the device. Click "OK".

or

From a PowerCLI command prompt while connected to the ESXi host or vCenter server, run the following command:

Get-VM "VM Name" | Get-PassthroughDevice | Remove-PassthroughDevice'
  impact 0.5
  tag check_id: 'C-62467r933240_chk'
  tag severity: 'medium'
  tag gid: 'V-258727'
  tag rid: 'SV-258727r933242_rule'
  tag stig_id: 'VMCH-80-000214'
  tag gtitle: 'SRG-OS-000480-VMM-002000'
  tag fix_id: 'F-62376r933241_fix'
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
      command = "Get-VM -Name '#{vm}' | Get-PassthroughDevice"
      result = powercli_command(command).stdout.strip
      describe "Checking the VM: #{vm} for PCI passthrough devices" do
        subject { result }
        it { should be_empty }
      end
    end
  else
    describe 'No VMs found!' do
      skip 'No VMs found...skipping tests'
    end
  end
end
