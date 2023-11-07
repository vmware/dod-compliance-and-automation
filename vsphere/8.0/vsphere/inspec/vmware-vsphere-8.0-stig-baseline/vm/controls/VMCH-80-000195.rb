control 'VMCH-80-000195' do
  title 'Virtual machines (VMs) must limit console sharing.'
  desc "By default, more than one user at a time can connect to remote console sessions. When multiple sessions are activated, each terminal window receives a notification about the new session. If an administrator in the VM logs in using a VMware remote console during their session, a nonadministrator in the VM might connect to the console and observe the administrator's actions.

Also, this could result in an administrator losing console access to a VM. For example, if a jump box is being used for an open console session and the administrator loses connection to that box, the console session remains open. Allowing two console sessions permits debugging via a shared session. For the highest security, allow only one remote console session at a time."
  desc 'check', 'For each virtual machine do the following:

From the vSphere Client, right-click the Virtual Machine and go to Edit Settings >> Advanced Parameters.

Verify the "RemoteDisplay.maxConnections" value is set to "1".

or

From a PowerCLI command prompt while connected to the ESXi host or vCenter server, run the following command:

Get-VM "VM Name" | Get-AdvancedSetting -Name RemoteDisplay.maxConnections

If the virtual machine advanced setting "RemoteDisplay.maxConnections" does not exist or is not set to "1", this is a finding.'
  desc 'fix', 'For each virtual machine do the following:

From the vSphere Client, right-click the Virtual Machine and go to Edit Settings >> Advanced Parameters.

Find the "RemoteDisplay.maxConnections" value and set it to "1".

If the setting does not exist, add the Name and Value setting at the bottom of screen.

or

From a PowerCLI command prompt while connected to the ESXi host or vCenter server, run the following command:

Get-VM "VM Name" | Get-AdvancedSetting -Name RemoteDisplay.maxConnections | Set-AdvancedSetting -Value 1

Note: The VM must be powered off to configure the advanced settings through the vSphere Client. Therefore, it is recommended to configure these settings with PowerCLI as this can be done while the VM is powered on. Settings do not take effect via either method until the virtual machine is cold started, not rebooted.'
  impact 0.5
  tag check_id: 'C-62448r933183_chk'
  tag severity: 'medium'
  tag gid: 'V-258708'
  tag rid: 'SV-258708r933185_rule'
  tag stig_id: 'VMCH-80-000195'
  tag gtitle: 'SRG-OS-000480-VMM-002000'
  tag fix_id: 'F-62357r933184_fix'
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
      result = powercli_command(command).stdout.strip
      describe "VM: #{vm}" do
        subject { result }
        it { should cmp '1' }
      end
    end
  else
    describe 'No VMs found!' do
      skip 'No VMs found...skipping tests'
    end
  end
end
