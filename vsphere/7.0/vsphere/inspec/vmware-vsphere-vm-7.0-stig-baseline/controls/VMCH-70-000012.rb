# encoding: UTF-8

control 'VMCH-70-000012' do
  title 'Unauthorized USB devices must be disconnected on the virtual machine.'
  desc  "Ensure that no device is connected to a virtual machine if it is not
required. For example, floppy, serial and parallel ports are rarely used for
virtual machines in a datacenter environment, and CD/DVD drives are usually
connected only temporarily during software installation."
  desc  'rationale', ''
  desc  'check', "
    From the vSphere Client right-click the Virtual Machine and go to Edit
Settings. Review the VMs hardware and verify no USB devices exist.

    or

    From a PowerCLI command prompt while connected to the ESXi host or vCenter
server, run the following commands:

    Get-VM | Where {$_.ExtensionData.Config.Hardware.Device.DeviceInfo.Label
-match \"usb\"}
    Get-VM | Get-UsbDevice

    If a virtual machine has any USB devices or USB controllers present, this
is a finding.

    If USB smart card readers are used to pass smart cards through the VM
console to a VM then the use of a USB controller and USB devices for that
purpose is not a finding.
  "
  desc  'fix', "
    From the vSphere Client right-click the Virtual Machine and go to Edit
Settings. Select the USB controller and click the circle-x to remove then OK.

    or

    From a PowerCLI command prompt while connected to the ESXi host or vCenter
server, run the following command:

    Get-VM \"VM Name\" | Get-USBDevice | Remove-USBDevice

    Note:  This will not remove the USB controller just any connected devices.
  "
  impact 0.5
  tag severity: 'medium'
  tag gtitle: 'SRG-OS-000480-VMM-002000'
  tag gid: nil
  tag rid: nil
  tag stig_id: 'VMCH-70-000012'
  tag fix_id: nil
  tag cci: 'CCI-000366'
  tag nist: ['CM-6 b']

  command = "(Get-VM -Name #{input('vmName')}).ExtensionData.Config.Hardware.Device.DeviceInfo.label"
  describe powercli_command(command) do
    its ('stdout') { should_not match 'USB' }
    its ('exit_status') { should cmp 0 }
  end

end

