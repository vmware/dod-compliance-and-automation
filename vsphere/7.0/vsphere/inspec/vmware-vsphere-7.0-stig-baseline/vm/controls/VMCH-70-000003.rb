control 'VMCH-70-000003' do
  title 'Paste operations must be disabled on the virtual machine (VM).'
  desc 'Copy and paste operations are disabled by default; however, explicitly disabling this feature will enable audit controls to verify this setting is correct. Copy, paste, drag and drop, or GUI copy/paste operations between the guest operating system and the remote console could provide the means for an attacker to compromise the VM.'
  desc 'check', 'From the vSphere Client, right-click the Virtual Machine and go to Edit Settings >> VM Options >> Advanced >> Configuration Parameters >> Edit Configuration.

Verify the "isolation.tools.paste.disable" value is set to "true".

or

From a PowerCLI command prompt while connected to the ESXi host or vCenter server, run the following command:

Get-VM "VM Name" | Get-AdvancedSetting -Name isolation.tools.paste.disable

If the virtual machine advanced setting "isolation.tools.paste.disable" does not exist or is not set to "true", this is a finding.'
  desc 'fix', 'From the vSphere Client, right-click the Virtual Machine and go to Edit Settings >> VM Options >> Advanced >> Configuration Parameters >> Edit Configuration.

Find the "isolation.tools.paste.disable" value and set it to "true".

If the setting does not exist, add the Name and Value setting at the bottom of screen.

Note: The VM must be powered off to configure the advanced settings through the vSphere Client. Therefore, it is recommended to configure these settings with PowerCLI as this can be done while the VM is powered on. Settings do not take effect via either method until the virtual machine is cold started, not rebooted.

or

From a PowerCLI command prompt while connected to the ESXi host or vCenter server, run the provided commands as shown below.

If the setting does not exist, run:

Get-VM "VM Name" | New-AdvancedSetting -Name isolation.tools.paste.disable -Value true

If the setting exists, run:

Get-VM "VM Name" | Get-AdvancedSetting -Name isolation.tools.paste.disable | Set-AdvancedSetting -Value true'
  impact 0.3
  tag check_id: 'C-60127r886397_chk'
  tag severity: 'low'
  tag gid: 'V-256452'
  tag rid: 'SV-256452r886399_rule'
  tag stig_id: 'VMCH-70-000003'
  tag gtitle: 'SRG-OS-000480-VMM-002000'
  tag fix_id: 'F-60070r886398_fix'
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
      command = "Get-VM -Name '#{vm}' | Get-AdvancedSetting -Name isolation.tools.paste.disable | Select-Object -ExpandProperty Value"
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
