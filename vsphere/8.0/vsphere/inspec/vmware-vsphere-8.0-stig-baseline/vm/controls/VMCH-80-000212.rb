control 'VMCH-80-000212' do
  title 'Virtual machines (VMs) must remove unneeded serial devices.'
  desc  'Ensure no device is connected to a virtual machine if it is not required. For example, floppy, serial, and parallel ports are rarely used for virtual machines in a data center environment, and CD/DVD drives are usually connected only temporarily during software installation.'
  desc  'rationale', ''
  desc  'check', "
    For each virtual machine do the following:

    From the vSphere Client, right-click the Virtual Machine and go to \"Edit Settings\".

    Review the VMs hardware and verify no serial devices exist.

    or

    From a PowerCLI command prompt while connected to the ESXi host or vCenter server, run the following command:

    Get-VM | Where {$_.ExtensionData.Config.Hardware.Device.DeviceInfo.Label -match \"serial\"}

    If a virtual machine has a serial device present, this is a finding.
  "
  desc  'fix', "
    The VM must be powered off to remove a serial device.

    For each virtual machine do the following:

    From the vSphere Client, right-click the Virtual Machine and go to \"Edit Settings\".

    Select the serial device, click the circled \"X\" to remove it, and click \"OK\".
  "
  impact 0.5
  tag severity: 'medium'
  tag gtitle: 'SRG-OS-000480-VMM-002000'
  tag gid: 'V-VMCH-80-000212'
  tag rid: 'SV-VMCH-80-000212'
  tag stig_id: 'VMCH-80-000212'
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
      command = "(Get-VM -Name '#{vm}').ExtensionData.Config.Hardware.Device.DeviceInfo.label"
      result = powercli_command(command).stdout.strip
      describe "Checking the VM: #{vm} for serial devices" do
        subject { result }
        it { should_not match 'Serial' }
      end
    end
  else
    describe 'No VMs found!' do
      skip 'No VMs found...skipping tests'
    end
  end
end
