control 'VMCH-80-000200' do
  title 'Virtual machines (VMs) must disable access through the "dvfilter" network Application Programming Interface (API).'
  desc  'An attacker might compromise a VM by using the "dvFilter" API. Configure only VMs that need this access to use the API.'
  desc  'rationale', ''
  desc  'check', "
    For each virtual machine do the following:

    From the vSphere Client, right-click the Virtual Machine and go to Edit Settings >> Advanced Parameters.

    Verify the settings with the format \"ethernet*.filter*.name\" do not exist.

    or

    From a PowerCLI command prompt while connected to the ESXi host or vCenter server, run the following command:

    Get-VM \"VM Name\" | Get-AdvancedSetting -Name \"ethernet*.filter*.name*\"

    If the virtual machine advanced setting \"ethernet*.filter*.name\" exists and dvfilters are not in use, this is a finding.

    If the virtual machine advanced setting \"ethernet*.filter*.name\" exists and the value is not valid, this is a finding.
  "
  desc  'fix', "
    For each virtual machine do the following:

    From the vSphere Client, right-click the Virtual Machine and go to Edit Settings >> Advanced Parameters.

    Look for settings with the format \"ethernet*.filter*.name\".

    Ensure only required VMs use this setting.

    or

    From a PowerCLI command prompt while connected to the ESXi host or vCenter server, run the following command:

    Get-VM \"VM Name\" | Get-AdvancedSetting -Name ethernetX.filterY.name | Remove-AdvancedSetting

    Note: Change the X and Y values to match the specific setting in the organization's environment.

    Note: The VM must be powered off to configure the advanced settings through the vSphere Client. Therefore, it is recommended to configure these settings with PowerCLI as this can be done while the VM is powered on. Settings do not take effect via either method until the virtual machine is cold started, not rebooted.
  "
  impact 0.3
  tag severity: 'low'
  tag gtitle: 'SRG-OS-000480-VMM-002000'
  tag gid: 'V-VMCH-80-000200'
  tag rid: 'SV-VMCH-80-000200'
  tag stig_id: 'VMCH-80-000200'
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
      command = "Get-VM -Name '#{vm}' | Get-AdvancedSetting -Name ethernet*.filter* | Select-Object -ExpandProperty Value"
      result = powercli_command(command).stdout.strip
      describe "VM: #{vm}" do
        subject { result }
        it { should be_empty }
      end
    end
  else
    describe 'No VMs found!' do
      skip 'No VMs found...skipping tests'
    end
  end
end
