control 'VCFV-9X-000202' do
  title 'Virtual machines (VMs) must prevent unauthorized removal, connection, and modification of devices.'
  desc  "
    In a virtual machine, users and processes without root or administrator privileges can connect or disconnect devices, such as network adaptors and CD-ROM drives, and can modify device settings. Use the virtual machine settings editor or configuration editor to remove unneeded or unused hardware devices. To use the device again, prevent a user or running process in the virtual machine from connecting, disconnecting, or modifying a device from within the guest operating system.

    By default, a rogue user with nonadministrator privileges in a virtual machine can:

    1. Connect a disconnected CD-ROM drive and access sensitive information on the media left in the drive.
    2. Disconnect a network adapter to isolate the virtual machine from its network, which is a denial of service.
    3. Modify settings on a device.
  "
  desc  'rationale', ''
  desc  'check', "
    For each virtual machine do the following:

    From the vSphere Client, right-click the Virtual Machine and go to Edit Settings >> Advanced Parameters.

    Verify the \"isolation.device.connectable.disable\" value is set to \"true\".

    or

    From a PowerCLI command prompt while connected to the ESX host or vCenter server, run the following command:

    Get-VM \"VM Name\" | Get-AdvancedSetting -Name isolation.device.connectable.disable

    If the virtual machine advanced setting \"isolation.device.connectable.disable\" is not set to \"true\", this is a finding.

    If the virtual machine advanced setting \"isolation.device.connectable.disable\" does not exist, this is not a finding.
  "
  desc  'fix', "
    For each virtual machine do the following:

    From the vSphere Client, right-click the Virtual Machine and go to Edit Settings >> Advanced Parameters.

    Find the \"isolation.device.connectable.disable\" value and set it to \"true\".

    If the setting does not exist no action is needed.

    or

    From a PowerCLI command prompt while connected to the ESX host or vCenter server, run the following command:

    Get-VM \"VM Name\" | Get-AdvancedSetting -Name isolation.device.connectable.disable | Set-AdvancedSetting -Value true

    Note: The VM must be powered off to configure the advanced settings through the vSphere Client. Therefore, it is recommended to configure these settings with PowerCLI as this can be done while the VM is powered on. Settings do not take effect via either method until the virtual machine is cold started, not rebooted.
  "
  impact 0.5
  tag severity: 'medium'
  tag gtitle: 'SRG-OS-000480-VMM-002000'
  tag gid: 'V-VCFV-9X-000202'
  tag rid: 'SV-VCFV-9X-000202'
  tag stig_id: 'VCFV-9X-000202'
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']

  vmName = input('vm_Name')
  vmcluster = input('vm_cluster')
  allvms = input('vm_allvms')
  vms = []
  advSettingName = 'isolation.device.connectable.disable'

  unless vmName.blank?
    vms = powercli_command("Get-VM -Name '#{vmName}' | Sort-Object Name | Select-Object -ExpandProperty Name").stdout.gsub("\r\n", "\n").split("\n")
  end
  unless vmcluster.blank?
    vms = powercli_command("Get-VM -Location (Get-Cluster -Name '#{vmcluster}') | Sort-Object Name | Select-Object -ExpandProperty Name").stdout.gsub("\r\n", "\n").split("\n")
  end
  unless allvms == false
    vms = powercli_command('Get-VM | Sort-Object Name | Select-Object -ExpandProperty Name').stdout.gsub("\r\n", "\n").split("\n")
  end

  if vms.blank?
    describe 'No virtual machines found by name or in target vCenter...skipping test. Troubleshoot issue and rerun scan.' do
      skip 'No virtual machines found by name or in target vCenter...skipping test. Troubleshoot issue and rerun scan.'
    end
  else
    vms.each do |vm|
      command = "Get-VM -Name '#{vm}' | Get-AdvancedSetting -Name #{advSettingName} | Select-Object Name,Value,Entity | ConvertTo-Json -Depth 0 -WarningAction SilentlyContinue"
      result = powercli_command(command).stdout.strip

      describe "The setting: #{advSettingName} on VM: #{vm}" do
        subject { json(content: result) }
        its(['Value']) { should cmp('true').or be_blank }
      end
    end
  end
end
