control 'VMCH-70-000028' do
  title 'DirectPath I/O must be disabled on the virtual machine when not required.'
  desc  'VMDirectPath I/O (PCI passthrough) enables direct assignment of hardware PCI functions to virtual machines. This gives the virtual machine access to the PCI functions with minimal intervention from the ESXi host. This is a powerful feature for legitimate applications such as virtualized storage appliances, backup appliances, dedicated graphics, etc, but it also allows a potential attacker highly privileged access to underlying hardware and the PCI bus. '
  desc  'rationale', ''
  desc  'check', "
    From the vSphere Client select the Virtual Machine, right click and go to Edit Settings >> VM Options Tab >> Advanced >> Configuration Parameters >> Edit Configuration.

    Find any \"pciPassthruX.present\" value (where X is a count starting at 0) and verify it is set to \"FALSE\" or \"\".

    or

    From a PowerCLI command prompt while connected to the ESXi host or vCenter server, run the following command:

    Get-VM \"VM Name\" | Get-AdvancedSetting -Name \"pciPassthru*.present\" | Select Entity, Name, Value

    If the virtual machine advanced setting \"pciPassthruX.present\" is present, and the specific device returned is not approved, this is a finding.

    If the virtual machine advanced setting \"pciPassthruX.present\" is not present, this is not a finding.
  "
  desc 'fix', "
    From the vSphere Client select the Virtual Machine, right click and go to Edit Settings >> Virtual Hardware Tab.

    Find the unexpected PCI device returned from the check.

    Hover the mouse over the device and click the circled 'X' to remove the device. Click \"OK\".

    or

    From a PowerCLI command prompt while connected to the ESXi host or vCenter server, run the following command:

    Get-VM \"VM Name\" | Get-AdvancedSetting -Name pciPassthruX.present | Remove-AdvancedSetting

    Note:  Change the X  value to match the specific setting in your environment.
  "
  impact 0.5
  tag severity: 'medium'
  tag gtitle: 'SRG-OS-000480-VMM-002000'
  tag gid: nil
  tag rid: nil
  tag stig_id: 'VMCH-70-000028'
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
      command = "Get-VM -Name #{vm} | Get-AdvancedSetting -Name pciPassthru*.present | Select-Object -ExpandProperty Value"
      describe powercli_command(command) do
        its('stdout.strip') { should be_empty }
      end
    end
  else
    describe 'No VMs found!' do
      skip 'No VMs found...skipping tests'
    end
  end
end
