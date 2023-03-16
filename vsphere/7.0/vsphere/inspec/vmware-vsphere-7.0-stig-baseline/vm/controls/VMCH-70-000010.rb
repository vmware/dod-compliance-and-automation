control 'VMCH-70-000010' do
  title 'Unauthorized parallel devices must be disconnected on the virtual machine (VM).'
  desc  'Ensure no device is connected to a virtual machine if it is not required. For example, floppy, serial, and parallel ports are rarely used for virtual machines in a data center environment, and CD/DVD drives are usually connected only temporarily during software installation.'
  desc  'rationale', ''
  desc  'check', "
    From the vSphere Client, right-click the Virtual Machine and go to \"Edit Settings\".

    Review the VMs hardware and verify no parallel devices exist.

    or

    From a PowerCLI command prompt while connected to the ESXi host or vCenter server, run the following command:

    Get-VM | Where {$_.ExtensionData.Config.Hardware.Device.DeviceInfo.Label -match \"parallel\"}

    If a virtual machine has a parallel device present, this is a finding.
  "
  desc  'fix', "
    The VM must be powered off to remove a parallel device.

    From the vSphere Client, right-click the Virtual Machine and go to \"Edit Settings\".

    Select the parallel device, click the circled \"X\" to remove it, and click \"OK\".
  "
  impact 0.5
  tag severity: 'medium'
  tag gtitle: 'SRG-OS-000480-VMM-002000'
  tag gid: 'V-256459'
  tag rid: 'SV-256459r886420_rule'
  tag stig_id: 'VMCH-70-000010'
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']

  vmName = input('vmName')
  allvms = input('allvms')
  vms = []

  unless vmName.empty?
    vms = powercli_command("Get-VM -Name #{vmName} | Sort-Object Name | Select -ExpandProperty Name").stdout.gsub("\r\n", "\n").split("\n")
  end
  unless allvms == false
    vms = powercli_command('Get-VM | Sort-Object Name | Select -ExpandProperty Name').stdout.gsub("\r\n", "\n").split("\n")
  end

  if !vms.empty?
    vms.each do |vm|
      command = "(Get-VM -Name '#{vm}').ExtensionData.Config.Hardware.Device.DeviceInfo.label"
      describe powercli_command(command) do
        its('stdout') { should_not match 'Parallel' }
      end
    end
  else
    describe 'No VMs found!' do
      skip 'No VMs found...skipping tests'
    end
  end
end
