control 'VMCH-80-000213' do
  title 'Virtual machines (VMs) must remove unneeded USB devices.'
  desc  'Ensure no device is connected to a virtual machine if it is not required. For example, floppy, serial, and parallel ports are rarely used for virtual machines in a data center environment, and CD/DVD drives are usually connected only temporarily during software installation.'
  desc  'rationale', ''
  desc  'check', "
    For each virtual machine do the following:

    From the vSphere Client, right-click the Virtual Machine and go to \"Edit Settings\".

    Review the VMs hardware and verify no USB devices exist.

    or

    From a PowerCLI command prompt while connected to the ESXi host or vCenter server, run the following commands:

    Get-VM | Where {$_.ExtensionData.Config.Hardware.Device.DeviceInfo.Label -match \"usb\"}
    Get-VM | Get-UsbDevice

    If a virtual machine has any USB devices or USB controllers present, this is a finding.

    If USB smart card readers are used to pass smart cards through the VM console to a VM, the use of a USB controller and USB devices for that purpose is not a finding.
  "
  desc  'fix', "
    For each virtual machine do the following:

    From the vSphere Client, right-click the Virtual Machine and go to \"Edit Settings\".

    Select the USB controller, click the circled \"X\" to remove it, and click \"OK\".

    or

    From a PowerCLI command prompt while connected to the ESXi host or vCenter server, run the following command:

    Get-VM \"VM Name\" | Get-USBDevice | Remove-USBDevice

    Note:  This will not remove the USB controller, just any connected devices.
  "
  impact 0.5
  tag severity: 'medium'
  tag gtitle: 'SRG-OS-000480-VMM-002000'
  tag gid: 'V-VMCH-80-000213'
  tag rid: 'SV-VMCH-80-000213'
  tag stig_id: 'VMCH-80-000213'
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
      describe "Checking the VM: #{vm} for USB devices" do
        subject { result }
        it { should_not match 'USB' }
      end
    end
  else
    describe 'No VMs found!' do
      skip 'No VMs found...skipping tests'
    end
  end
end
