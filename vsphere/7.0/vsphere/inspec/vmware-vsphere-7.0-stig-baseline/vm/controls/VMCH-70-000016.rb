control 'VMCH-70-000016' do
  title 'Unauthorized removal, connection and modification of devices must be prevented on the virtual machine.'
  desc  "
    In a virtual machine, users and processes without root or administrator privileges can connect or disconnect devices, such as network adaptors and CD-ROM drives, and can modify device settings. Use the virtual machine settings editor or configuration editor to remove unneeded or unused hardware devices. To use the device again, you can prevent a user or running process in the virtual machine from connecting, disconnecting, or modifying a device from within the guest operating system.

    By default, a rogue user with nonadministrator privileges in a virtual machine can:
    1. Connect a disconnected CD-ROM drive and access sensitive information on the media left in the drive
    2. Disconnect a network adaptor to isolate the virtual machine from its network, which is a denial of service
    3. Modify settings on a device
  "
  desc  'rationale', ''
  desc  'check', "
    From the vSphere Client right-click the Virtual Machine and go to Edit Settings >> VM Options >> Advanced >> Configuration Parameters >> Edit Configuration.

    Verify the \"isolation.device.connectable.disable\" value is set to \"true\".

    or

    From a PowerCLI command prompt while connected to the ESXi host or vCenter server, run the following command:

    Get-VM \"VM Name\" | Get-AdvancedSetting -Name isolation.device.connectable.disable

    If the virtual machine advanced setting \"isolation.device.connectable.disable\" does not exist or is not set to \"true\", this is a finding.
  "
  desc 'fix', "
    From the vSphere Client right-click the Virtual Machine and go to Edit Settings >> VM Options >> Advanced >> Configuration Parameters >> Edit Configuration.

    Find the \"isolation.device.connectable.disable\" value and set it to \"true\".

    If the setting does not exist, add the Name and Value setting at the bottom of screen.

    Note: The VM must be powered off to configure the advanced settings through the vSphere Client so it is recommended to configure these settings with PowerCLI as it can be done while the VM is powered on. Settings do not take effect via either method until the virtual machine is cold started, not rebooted.

    or

    From a PowerCLI command prompt while connected to the ESXi host or vCenter server, run the following command:

    If the setting does not exist, run:

    Get-VM \"VM Name\" | New-AdvancedSetting -Name isolation.device.connectable.disable -Value true

    If the setting exists, run:

    Get-VM \"VM Name\" | Get-AdvancedSetting -Name isolation.device.connectable.disable | Set-AdvancedSetting -Value true
  "
  impact 0.5
  tag severity: 'medium'
  tag gtitle: 'SRG-OS-000480-VMM-002000'
  tag gid: nil
  tag rid: nil
  tag stig_id: 'VMCH-70-000016'
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']

  vmName = input('vmName')
  allvms = input('allvms')
  vms = []

  unless vmName.empty?
    vms = powercli_command("Get-VM -Name #{vmName} | Sort-Object Name | Select -ExpandProperty Name").stdout.split
  end
  unless allvms == false
    vms = powercli_command('Get-VM | Sort-Object Name | Select -ExpandProperty Name').stdout.split
  end

  if !vms.empty?
    vms.each do |vm|
      command = "Get-VM -Name #{vm} | Get-AdvancedSetting -Name isolation.device.connectable.disable | Select-Object -ExpandProperty Value"
      describe powercli_command(command) do
        its('stdout.strip') { should cmp 'true' }
      end
    end
  else
    describe 'No VMs found!' do
      skip 'No VMs found...skipping tests'
    end
  end
end
