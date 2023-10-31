control 'VMCH-80-000206' do
  title 'Virtual machines (VMs) must configure log retention.'
  desc  "
    The ESXi hypervisor maintains logs for each individual VM by default. These logs contain information including but not limited to power events, system failure information, tools status and activity, time sync, virtual hardware changes, vMotion migrations, and machine clones.

    By default, 10 of these logs are retained. This is normally sufficient for most environments, but this configuration must be verified and maintained.
  "
  desc  'rationale', ''
  desc  'check', "
    For each virtual machine do the following:

    From the vSphere Client, right-click the Virtual Machine and go to Edit Settings >> Advanced Parameters.

    Verify the \"log.keepOld\" value is set to \"10\".

    or

    From a PowerCLI command prompt while connected to the ESXi host or vCenter server, run the following command:

    Get-VM \"VM Name\" | Get-AdvancedSetting -Name log.keepOld

    If the virtual machine advanced setting \"log.keepOld\" is not set to \"10\", this is a finding.

    If the virtual machine advanced setting \"log.keepOld\" does not exist, this is not a finding.
  "
  desc  'fix', "
    For each virtual machine do the following:

    From the vSphere Client, right-click the Virtual Machine and go to Edit Settings >> Advanced Parameters.

    Find the \"log.keepOld\" value and set it to \"10\".

    If the setting does not exist no action is needed.

    or

    From a PowerCLI command prompt while connected to the ESXi host or vCenter server, run the following command:

    Get-VM \"VM Name\" | Get-AdvancedSetting -Name log.keepOld | Set-AdvancedSetting -Value 10

    Note: The VM must be powered off to configure the advanced settings through the vSphere Client. Therefore, it is recommended to configure these settings with PowerCLI as this can be done while the VM is powered on. Settings do not take effect via either method until the virtual machine is cold started, not rebooted.
  "
  impact 0.5
  tag severity: 'medium'
  tag gtitle: 'SRG-OS-000480-VMM-002000'
  tag gid: 'V-VMCH-80-000206'
  tag rid: 'SV-VMCH-80-000206'
  tag stig_id: 'VMCH-80-000206'
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
      command = "Get-VM -Name '#{vm}' | Get-AdvancedSetting -Name log.keepOld | Select-Object -ExpandProperty Value"
      result = powercli_command(command).stdout.strip
      describe.one do
        describe "VM: #{vm}" do
          subject { result }
          it { should cmp '10' }
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
