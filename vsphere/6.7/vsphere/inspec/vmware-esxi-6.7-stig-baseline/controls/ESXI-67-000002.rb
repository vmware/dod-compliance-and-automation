control "ESXI-67-000002" do
  title "The ESXi host must verify the DCUI.Access list."
  desc  "Lockdown mode disables direct host access requiring that admins manage
hosts from vCenter Server.  However, if a host becomes isolated from vCenter
Server, the admin is locked out and can no longer manage the host. If you are
using normal lockdown mode, you can avoid becoming locked out of an ESXi host
that is running in lockdown mode, by setting DCUI.Access to a list of highly
trusted users who can override lockdown mode and access the DCUI. The DCUI is
not running in strict lockdown mode."
  impact 0.3
  tag severity: "CAT III"
  tag gtitle: "SRG-OS-000480-VMM-002000"
  tag rid: "ESXI-67-000002"
  tag stig_id: "ESXI-67-000002"
  tag cci: "CCI-000366"
  tag nist: ["CM-6 b", "Rev_4"]
  desc 'check', "From the vSphere Client select the ESXi Host and go to Configure
>> System >> Advanced System Settings.  Select the DCUI.Access value and verify
only the root user is listed.

or

From a PowerCLI command prompt while connected to the ESXi host run the
following command:

Get-VMHost | Get-AdvancedSetting -Name DCUI.Access and verify it is set to root.

If the DCUI.Access is not restricted to root, this is a finding.

Note: This list is only for local user accounts and should only contain the
root user.

For environments that do not use vCenter server to manage ESXi, this is not
applicable."
  desc 'fix', "From the vSphere Client select the ESXi Host and go to Configure >>
System >> Advanced System Settings.  Click Edit and select the DCUI.Access
value and configure it to root.

or

From a PowerCLI command prompt while connected to the ESXi host run the
following command:

Get-VMHost | Get-AdvancedSetting -Name DCUI.Access | Set-AdvancedSetting -Value
\"root\""

  command = "(Get-VMHost -Name #{input('vmhostName')}) | Get-AdvancedSetting -Name DCUI.Access | Select-Object -ExpandProperty Value"
  describe powercli_command(command) do
    its('stdout.strip') { should match "root" }
  end

end

