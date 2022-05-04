control 'VMCH-70-000019' do
  title 'Access to virtual machines through the dvfilter network APIs must be controlled.'
  desc  'An attacker might compromise a VM by making use the dvFilter API. Configure only those VMs to use the API that need this access.'
  desc  'rationale', ''
  desc  'check', "
    From the vSphere Client right-click the Virtual Machine and go to Edit Settings >> VM Options >> Advanced >> Configuration Parameters >> Edit Configuration.

    Look for settings with the format \"ethernet*.filter*.name\".

    or

    From a PowerCLI command prompt while connected to the ESXi host or vCenter server, run the following command:

    Get-VM \"VM Name\" | Get-AdvancedSetting -Name \"ethernet*.filter*.name*\"

    If the virtual machine advanced setting \"ethernet*.filter*.name\" exists and dvfilters are not in use, this is a finding.

    If the virtual machine advanced setting \"ethernet*.filter*.name\" exists and the value is not valid, this is a finding.
  "
  desc 'fix', "
    From the vSphere Client right-click the Virtual Machine and go to Edit Settings >> VM Options >> Advanced >> Configuration Parameters >> Edit Configuration.

    Look for settings with the format \"ethernet*.filter*.name\".

    Ensure only required VMs use this setting.

    Note: The VM must be powered off to configure the advanced settings through the vSphere Client so it is recommended to configure these settings with PowerCLI as it can be done while the VM is powered on. Settings do not take effect via either method until the virtual machine is cold started, not rebooted.

    or

    From a PowerCLI command prompt while connected to the ESXi host or vCenter server, run the following command:

    Get-VM \"VM Name\" | Get-AdvancedSetting -Name ethernetX.filterY.name | Remove-AdvancedSetting

    Note:  Change the X and Y values to match the specific setting in your environment.
  "
  impact 0.7
  tag severity: 'high'
  tag gtitle: 'SRG-OS-000480-VMM-002000'
  tag gid: nil
  tag rid: nil
  tag stig_id: 'VMCH-70-000019'
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
      command = "Get-VM -Name #{vm} | Get-AdvancedSetting -Name ethernet*.filter* | Select-Object -ExpandProperty Value"
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
