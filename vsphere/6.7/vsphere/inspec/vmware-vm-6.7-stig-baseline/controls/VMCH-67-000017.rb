control "VMCH-67-000017" do
  title "The virtual machine must not be able to obtain host information from
the hypervisor."
  desc  "If enabled, a VM can obtain detailed information about the physical
host. The default value for the parameter is FALSE. This setting should not be
TRUE unless a particular VM requires this information for performance
monitoring. An adversary potentially can use this information to inform further
attacks on the host."
  impact 0.5
  tag severity: "CAT II"
  tag gtitle: "SRG-OS-000480-VMM-002000"
  tag gid: nil
  tag rid: "VMCH-67-000017"
  tag stig_id: "VMCH-67-000017"
  tag cci: "CCI-000366"
  tag nist: ["CM-6 b", "Rev_4"]
  desc 'check', "From the vSphere Web Client right-click the Virtual Machine and
go to Edit Settings >> VM Options >> Advanced >> Configuration Parameters >>
Edit Configuration. Verify the tools.guestlib.enableHostInfo value is set to
false.

or

From a PowerCLI command prompt while connected to the ESXi host or vCenter
server, run the following command:

Get-VM \"VM Name\" | Get-AdvancedSetting -Name tools.guestlib.enableHostInfo

If the virtual machine advanced setting tools.guestlib.enableHostInfo does not
exist or is not set to false, this is a finding."
  desc 'fix', "From the vSphere Web Client right-click the Virtual Machine and go
to Edit Settings >> VM Options >> Advanced >> Configuration Parameters >> Edit
Configuration. Find the tools.guestlib.enableHostInfo value and set it to
false. If the setting does not exist, add the Name and Value setting at the
bottom of screen.

Note: The VM must be powered off to configure the advanced settings through the
vSphere Web Client so it is recommended to configure these settings with
PowerCLI as it can be done while the VM is powered on. Settings do not take
effect via either method until the virtual machine is cold started, not
rebooted.

or

From a PowerCLI command prompt while connected to the ESXi host or vCenter
server, run the following command:

If the setting does not exist, run:

Get-VM \"VM Name\" | New-AdvancedSetting -Name tools.guestlib.enableHostInfo
-Value false

If the setting exists, run:

Get-VM \"VM Name\" | Get-AdvancedSetting -Name tools.guestlib.enableHostInfo |
Set-AdvancedSetting -Value false"

  command = "(Get-VM -Name #{input('vmName')} | Get-AdvancedSetting -Name tools.guestlib.enableHostInfo).value"
  describe powercli_command(command).stdout.strip do
    it { should cmp "false" }
  end

end

