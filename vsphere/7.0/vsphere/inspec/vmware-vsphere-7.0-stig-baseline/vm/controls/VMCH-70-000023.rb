control 'VMCH-70-000023' do
  title 'All 3D features on the virtual machine (VM) must be disabled when not required.'
  desc  'For performance reasons, it is recommended that 3D acceleration be disabled on virtual machines that do not require 3D functionality (e.g., most server workloads or desktops not using 3D applications).'
  desc  'rationale', ''
  desc  'check', "
    From the vSphere Client, select the Virtual Machine, right click and go to Edit Settings >> VM Options tab >> Advanced >> Configuration Parameters >> Edit Configuration.

    Find the \"mks.enable3d\" value and verify it is set to \"false\".

    or

    From a PowerCLI command prompt while connected to the ESXi host or vCenter server, run the following command:

    Get-VM \"VM Name\" | Get-AdvancedSetting -Name mks.enable3d

    If the virtual machine advanced setting \"mks.enable3d\" does not exist or is not set to \"false\", this is a finding.

    If a virtual machine requires 3D features, this is not a finding.
  "
  desc 'fix', "
    From the vSphere Client, select the Virtual Machine, right click and go to Edit Settings >> VM Options tab >> Advanced >> Configuration Parameters >> Edit Configuration.

    Find the \"mks.enable3d\" value and set it to \"false\".

    Note: The VM must be powered off to configure the advanced settings through the vSphere Client. Therefore, it is recommended to configure these settings with PowerCLI as this can be done while the VM is powered on. Settings do not take effect via either method until the virtual machine is cold started, not rebooted.

    or

    From a PowerCLI command prompt while connected to the ESXi host or vCenter server, run the provided commands as noted below.

    If the setting does not exist, run:

    Get-VM \"VM Name\" | New-AdvancedSetting -Name mks.enable3d -Value false

    If the setting exists, run:

    Get-VM \"VM Name\" | Get-AdvancedSetting -Name mks.enable3d | Set-AdvancedSetting -Value false
  "
  impact 0.3
  tag severity: 'low'
  tag gtitle: 'SRG-OS-000480-VMM-002000'
  tag gid: 'V-256471'
  tag rid: 'SV-256471r886456_rule'
  tag stig_id: 'VMCH-70-000023'
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
      command = "Get-VM -Name '#{vm}' | Get-AdvancedSetting -Name mks.enable3d | Select-Object -ExpandProperty Value"
      describe powercli_command(command) do
        its('stdout.strip') { should cmp 'false' }
      end
    end
  else
    describe 'No VMs found!' do
      skip 'No VMs found...skipping tests'
    end
  end
end
