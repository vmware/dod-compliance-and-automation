control "VMCH-67-000002" do
  title "Drag and drop operations must be disabled on the virtual machine."
  desc  "Copy and paste operations are disabled by default; however, by
explicitly disabling this feature it will enable audit controls to check that
this setting is correct. Copy, paste, drag and drop, or GUI copy/paste
operations between the guest OS and the remote console could provide the means
for an attacker to compromise the VM."
  impact 0.3
  tag severity: "CAT III"
  tag gtitle: "SRG-OS-000480-VMM-002000"
  tag gid: nil
  tag rid: "VMCH-67-000002"
  tag stig_id: "VMCH-67-000002"
  tag cci: "CCI-000366"
  tag nist: ["CM-6 b", "Rev_4"]
  desc 'check', "From the vSphere Web Client right-click the Virtual Machine and
go to Edit Settings >> VM Options >> Advanced >> Configuration Parameters >>
Edit Configuration. Verify the isolation.tools.dnd.disable value is set to true.

or

From a PowerCLI command prompt while connected to the ESXi host or vCenter
server, run the following command:

Get-VM \"VM Name\" | Get-AdvancedSetting -Name isolation.tools.dnd.disable

If the virtual machine advanced setting isolation.tools.dnd.disable does not
exist or is not set to true, this is a finding."
  desc 'fix', "From the vSphere Web Client right-click the Virtual Machine and go
to Edit Settings >> VM Options >> Advanced >> Configuration Parameters >> Edit
Configuration. Verify the isolation.tools.dnd.disable value is set to true. If
the setting does not exist, add the Name and Value setting at the bottom of
screen.

Note: The VM must be powered off to configure the advanced settings through the
vSphere Web Client so it is recommended to configure these settings with
PowerCLI as it can be done while the VM is powered on. Settings do not take
effect via either method until the virtual machine is cold started, not
rebooted.

or

From a PowerCLI command prompt while connected to the ESXi host or vCenter
server, run the following command:

If the setting does not exist, run:

Get-VM \"VM Name\" | New-AdvancedSetting -Name isolation.tools.dnd.disable
-Value true

If the setting exists, run:

Get-VM \"VM Name\" | Get-AdvancedSetting -Name isolation.tools.dnd.disable |
Set-AdvancedSetting -Value true"

  command = "(Get-VM -Name #{input('vmName')} | Get-AdvancedSetting -Name isolation.tools.dnd.disable).value"
  describe powercli_command(command).stdout.strip do
    it { should cmp "true" }
  end

end

