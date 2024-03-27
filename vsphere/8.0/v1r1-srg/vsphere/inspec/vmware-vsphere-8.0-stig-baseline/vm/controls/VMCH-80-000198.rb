control 'VMCH-80-000198' do
  title 'Virtual machines (VMs) must not be able to obtain host information from the hypervisor.'
  desc  'If enabled, a VM can obtain detailed information about the physical host. The default value for the parameter is FALSE. This setting should not be TRUE unless a particular VM requires this information for performance monitoring. An adversary could use this information to inform further attacks on the host.'
  desc  'rationale', ''
  desc  'check', "
    For each virtual machine do the following:

    From the vSphere Client, right-click the Virtual Machine and go to Edit Settings >> Advanced Parameters.

    Verify the \"tools.guestlib.enableHostInfo\" value is set to \"false\".

    or

    From a PowerCLI command prompt while connected to the ESXi host or vCenter server, run the following command:

    Get-VM \"VM Name\" | Get-AdvancedSetting -Name tools.guestlib.enableHostInfo

    If the virtual machine advanced setting \"tools.guestlib.enableHostInfo\" is not set to \"false\", this is a finding.

    If the virtual machine advanced setting \"tools.guestlib.enableHostInfo\" does NOT exist, this is NOT a finding.
  "
  desc  'fix', "
    For each virtual machine do the following:

    From the vSphere Client, right-click the Virtual Machine and go to Edit Settings >> Advanced Parameters.

    Find the \"tools.guestlib.enableHostInfo\" value and set it to \"false\".

    If the setting does not exist no action is needed.

    or

    From a PowerCLI command prompt while connected to the ESXi host or vCenter server, run the following command:

    Get-VM \"VM Name\" | Get-AdvancedSetting -Name tools.guestlib.enableHostInfo | Set-AdvancedSetting -Value false

    Note: The VM must be powered off to configure the advanced settings through the vSphere Client. Therefore, it is recommended to configure these settings with PowerCLI as this can be done while the VM is powered on. Settings do not take effect via either method until the virtual machine is cold started, not rebooted.
  "
  impact 0.5
  tag severity: 'medium'
  tag gtitle: 'SRG-OS-000480-VMM-002000'
  tag gid: 'V-VMCH-80-000198'
  tag rid: 'SV-VMCH-80-000198'
  tag stig_id: 'VMCH-80-000198'
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
      command = "Get-VM -Name '#{vm}' | Get-AdvancedSetting -Name tools.guestlib.enableHostInfo | Select-Object -ExpandProperty Value"
      result = powercli_command(command).stdout.strip
      describe.one do
        describe "VM: #{vm}" do
          subject { result }
          it { should cmp 'false' }
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
