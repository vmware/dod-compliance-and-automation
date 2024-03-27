control 'VMCH-80-000211' do
  title 'Virtual machines (VMs) must remove unneeded parallel devices.'
  desc  'Ensure no device is connected to a virtual machine if it is not required. For example, floppy, serial, and parallel ports are rarely used for virtual machines in a data center environment, and CD/DVD drives are usually connected only temporarily during software installation.'
  desc  'rationale', ''
  desc  'check', "
    Parallel devices are no longer visible through the vSphere Client and must be done via the Application Programming Interface (API) or PowerCLI.

    From a PowerCLI command prompt while connected to the ESXi host or vCenter server, run the following command:

    Get-VM | Where {$_.ExtensionData.Config.Hardware.Device.DeviceInfo.Label -match \"parallel\"}

    If a virtual machine has a parallel device present, this is a finding.
  "
  desc 'fix', "
    Parallel devices are no longer visible through the vSphere Client and must be done via the Application Programming Interface (API) or PowerCLI.

    The VM must be powered off to remove a parallel device.

    From a PowerCLI command prompt while connected to the ESXi host or vCenter server, run the following commands:

    $pport = (Get-VM -Name <vmname>).ExtensionData.Config.Hardware.Device | Where {$_.DeviceInfo.Label -match \"Parallel\"}
    $spec = New-Object VMware.Vim.VirtualMachineConfigSpec
    $spec.DeviceChange += New-Object VMware.Vim.VirtualDeviceConfigSpec
    $spec.DeviceChange[-1].device = $pport
    $spec.DeviceChange[-1].operation = \"remove\"
    (Get-VM -Name <vmname>).ExtensionData.ReconfigVM($spec)
  "
  impact 0.5
  tag severity: 'medium'
  tag gtitle: 'SRG-OS-000480-VMM-002000'
  tag gid: 'V-VMCH-80-000211'
  tag rid: 'SV-VMCH-80-000211'
  tag stig_id: 'VMCH-80-000211'
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
      describe "Checking the VM: #{vm} for parallel devices" do
        subject { result }
        it { should_not match 'Parallel' }
      end
    end
  else
    describe 'No VMs found!' do
      skip 'No VMs found...skipping tests'
    end
  end
end
