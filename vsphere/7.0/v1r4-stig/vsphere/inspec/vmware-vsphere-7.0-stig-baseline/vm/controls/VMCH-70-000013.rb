control 'VMCH-70-000013' do
  title 'Console connection sharing must be limited on the virtual machine (VM).'
  desc "By default, more than one user at a time can connect to remote console sessions. When multiple sessions are activated, each terminal window receives a notification about the new session. If an administrator in the VM logs in using a VMware remote console during their session, a nonadministrator in the VM might connect to the console and observe the administrator's actions.

Also, this could result in an administrator losing console access to a VM. For example, if a jump box is being used for an open console session and the administrator loses connection to that box, the console session remains open. Allowing two console sessions permits debugging via a shared session. For the highest security, allow only one remote console session at a time."
  desc 'check', 'From the vSphere Client, right-click the Virtual Machine and go to Edit Settings >> VM Options >> Advanced >> Configuration Parameters >> Edit Configuration.

Verify the "RemoteDisplay.maxConnections" value is set to "1".

or

From a PowerCLI command prompt while connected to the ESXi host or vCenter server, run the following command:

Get-VM "VM Name" | Get-AdvancedSetting -Name RemoteDisplay.maxConnections

If the virtual machine advanced setting "RemoteDisplay.maxConnections" does not exist or is not set to "1", this is a finding.'
  desc 'fix', 'From the vSphere Client, right-click the Virtual Machine and go to Edit Settings >> VM Options >> Advanced >> Configuration Parameters >> Edit Configuration.

Find the "RemoteDisplay.maxConnections" value and set it to "1".

If the setting does not exist, add the Name and Value setting at the bottom of screen.

Note: The VM must be powered off to configure the advanced settings through the vSphere Client. Therefore, it is recommended to configure these settings with PowerCLI as this can be done while the VM is powered on. Settings do not take effect via either method until the virtual machine is cold started, not rebooted.

or

From a PowerCLI command prompt while connected to the ESXi host or vCenter server, run the provided commands as shown below.

If the setting does not exist, run:

Get-VM "VM Name" | New-AdvancedSetting -Name RemoteDisplay.maxConnections -Value 1

If the setting exists, run:

Get-VM "VM Name" | Get-AdvancedSetting -Name RemoteDisplay.maxConnections | Set-AdvancedSetting -Value 1'
  impact 0.5
  tag check_id: 'C-60137r886427_chk'
  tag severity: 'medium'
  tag gid: 'V-256462'
  tag rid: 'SV-256462r886429_rule'
  tag stig_id: 'VMCH-70-000013'
  tag gtitle: 'SRG-OS-000480-VMM-002000'
  tag fix_id: 'F-60080r886428_fix'
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
      command = "Get-VM -Name '#{vm}' | Get-AdvancedSetting -Name RemoteDisplay.maxConnections | Select-Object -ExpandProperty Value"
      describe powercli_command(command) do
        its('stdout.strip') { should cmp '1' }
      end
    end
  else
    describe 'No VMs found!' do
      skip 'No VMs found...skipping tests'
    end
  end
end
