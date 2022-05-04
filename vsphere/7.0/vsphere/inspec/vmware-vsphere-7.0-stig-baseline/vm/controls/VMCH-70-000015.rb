control 'VMCH-70-000015' do
  title 'Informational messages from the virtual machine to the VMX file must be limited on the virtual machine.'
  desc  "
    The configuration file containing these name-value pairs is limited to a size of 1MB. If not limited, VMware tools in the guest OS are capable of sending a large and continuous data stream to the host. This 1MB capacity should be sufficient for most cases, but this value can change if necessary.

    The value can be increased if large amounts of custom information are being stored in the configuration file. The default limit is 1MB.
  "
  desc  'rationale', ''
  desc  'check', "
    From the vSphere Client right-click the Virtual Machine and go to Edit Settings >> VM Options >> Advanced >> Configuration Parameters >> Edit Configuration.

    Verify the \"tools.setinfo.sizeLimit\" value is set to \"1048576\".

    or

    From a PowerCLI command prompt while connected to the ESXi host or vCenter server, run the following command:

    Get-VM \"VM Name\" | Get-AdvancedSetting -Name tools.setinfo.sizeLimit

    If the virtual machine advanced setting \"tools.setinfo.sizeLimit\" does not exist or is not set to \"1048576\", this is a finding.
  "
  desc 'fix', "
    From the vSphere Client right-click the Virtual Machine and go to Edit Settings >> VM Options >> Advanced >> Configuration Parameters >> Edit Configuration.

    Find the \"tools.setinfo.sizeLimit\" value and set it to \"1048576\".

    If the setting does not exist, add the Name and Value setting at the bottom of screen.

    Note: The VM must be powered off to configure the advanced settings through the vSphere Client so it is recommended to configure these settings with PowerCLI as it can be done while the VM is powered on. Settings do not take effect via either method until the virtual machine is cold started, not rebooted.

    or

    From a PowerCLI command prompt while connected to the ESXi host or vCenter server, run the following command:

    If the setting does not exist, run:

    Get-VM \"VM Name\" | New-AdvancedSetting -Name tools.setinfo.sizeLimit -Value 1048576

    If the setting exists, run:

    Get-VM \"VM Name\" | Get-AdvancedSetting -Name tools.setinfo.sizeLimit | Set-AdvancedSetting -Value 1048576
  "
  impact 0.7
  tag severity: 'high'
  tag gtitle: 'SRG-OS-000480-VMM-002000'
  tag gid: nil
  tag rid: nil
  tag stig_id: 'VMCH-70-000015'
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
      command = "Get-VM -Name #{vm} | Get-AdvancedSetting -Name tools.setinfo.sizeLimit | Select-Object -ExpandProperty Value"
      describe powercli_command(command) do
        its('stdout.strip') { should cmp '1048576' }
      end
    end
  else
    describe 'No VMs found!' do
      skip 'No VMs found...skipping tests'
    end
  end
end
