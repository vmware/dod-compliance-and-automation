control 'VMCH-70-000022' do
  title 'The virtual machine (VM) guest operating system must be locked when the last console connection is closed.'
  desc  'When accessing the VM console, the guest operating system must be locked when the last console user disconnects, limiting the possibility of session hijacking. This setting only applies to Windows-based VMs with VMware tools installed.'
  desc  'rationale', ''
  desc  'check', "
    From the vSphere Client, select the Virtual Machine, right click and go to Edit Settings >> VM Options tab >> Advanced >> Configuration Parameters >> Edit Configuration.

    Find the \"tools.guest.desktop.autolock\" value and verify that it is set to \"true\".

    or

    From a PowerCLI command prompt while connected to the ESXi host or vCenter server, run the following command:

    Get-VM \"VM Name\" | Get-AdvancedSetting -Name tools.guest.desktop.autolock

    If the virtual machine advanced setting \"tools.guest.desktop.autolock\" does not exist or is not set to \"true\", this is a finding.

    If the VM is not Windows-based, this is not a finding.
  "
  desc 'fix', "
    From the vSphere Client, select the Virtual Machine, right click and go to Edit Settings >> VM Options tab >> Advanced >> Configuration Parameters >> Edit Configuration.

    Find or create the \"tools.guest.desktop.autolock\" value and set it to \"true\".

    Note: The VM must be powered off to configure the advanced settings through the vSphere Client. Therefore, it is recommended to configure these settings with PowerCLI as this can be done while the VM is powered on. Settings do not take effect via either method until the virtual machine is cold started, not rebooted.

    or

    From a PowerCLI command prompt while connected to the ESXi host or vCenter server, run the provided commands as noted below.

    If the setting does not exist, run:

    Get-VM \"VM Name\" | New-AdvancedSetting -Name tools.guest.desktop.autolock -Value true

    If the setting exists, run:

    Get-VM \"VM Name\" | Get-AdvancedSetting -Name tools.guest.desktop.autolock | Set-AdvancedSetting -Value true
  "
  impact 0.5
  tag severity: 'medium'
  tag gtitle: 'SRG-OS-000480-VMM-002000'
  tag gid: 'V-256470'
  tag rid: 'SV-256470r886453_rule'
  tag stig_id: 'VMCH-70-000022'
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
      command = "Get-VM -Name '#{vm}' | Get-AdvancedSetting -Name tools.guest.desktop.autolock | Select-Object -ExpandProperty Value"
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
