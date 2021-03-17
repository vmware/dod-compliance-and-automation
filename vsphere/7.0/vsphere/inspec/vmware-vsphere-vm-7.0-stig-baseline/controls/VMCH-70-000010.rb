# encoding: UTF-8

control 'VMCH-70-000010' do
  title "Unauthorized parallel devices must be disconnected on the virtual
machine."
  desc  "Ensure that no device is connected to a virtual machine if it is not
required. For example, floppy, serial and parallel ports are rarely used for
virtual machines in a datacenter environment, and CD/DVD drives are usually
connected only temporarily during software installation."
  desc  'rationale', ''
  desc  'check', "
    From the vSphere Client right-click the Virtual Machine and go to Edit
Settings. Review the VMs hardware and verify no parallel devices exist.

    or

    From a PowerCLI command prompt while connected to the ESXi host or vCenter
server, run the following command:

    Get-VM | Where {$_.ExtensionData.Config.Hardware.Device.DeviceInfo.Label
-match \"parallel\"}

    If a virtual machine has a parallel device present, this is a finding.
  "
  desc  'fix', "
    The VM must be powered off in order to remove a parallel device.

    From the vSphere Client right-click the Virtual Machine and go to Edit
Settings. Select the parallel device and click the circle-x to remove then OK.
  "
  impact 0.5
  tag severity: 'medium'
  tag gtitle: 'SRG-OS-000480-VMM-002000'
  tag gid: nil
  tag rid: nil
  tag stig_id: 'VMCH-70-000010'
  tag fix_id: nil
  tag cci: 'CCI-000366'
  tag nist: ['CM-6 b']

  command = "(Get-VM -Name #{input('vmName')}).ExtensionData.Config.Hardware.Device.DeviceInfo.label"
  describe powercli_command(command) do
    its ('stdout') { should_not match 'Parallel' }
    its ('exit_status') { should cmp 0 }
  end

end

