control "ESXI-67-000041" do
  title "The ESXi host must set a timeout to automatically disable idle shell
sessions after two minutes."
  desc  "If a user forgets to log out of their local or remote ESXi Shell
session, the idle connection will remain open indefinitely and increase the
likelyhood of inapprioriate host access via session hijacking.  The
ESXiShellInteractiveTimeOut allows you to automatically terminate idle shell
sessions."
  impact 0.5
  tag severity: "CAT II"
  tag gtitle: "SRG-OS-000163-VMM-000700"
  tag rid: "ESXI-67-000041"
  tag stig_id: "ESXI-67-000041"
  tag cci: "CCI-001133"
  tag nist: ["SC-10", "Rev_4"]
  desc 'check', "From the vSphere Client select the ESXi Host and go to Configure
>> System >> Advanced System Settings. Select the
UserVars.ESXiShellInteractiveTimeOut value and verify it is set to 120 (2
Minutes).

or

From a PowerCLI command prompt while connected to the ESXi host run the
following command:

Get-VMHost | Get-AdvancedSetting -Name UserVars.ESXiShellInteractiveTimeOut

If the UserVars.ESXiShellInteractiveTimeOut setting is not set to 120, this is
a finding."
  desc 'fix', "From the vSphere Client select the ESXi Host and go to Configure >>
System >> Advanced System Settings. Click Edit and select the
UserVars.ESXiShellInteractiveTimeOut value and configure it to 120.

or

From a PowerCLI command prompt while connected to the ESXi host run the
following commands:

Get-VMHost | Get-AdvancedSetting -Name UserVars.ESXiShellInteractiveTimeOut |
Set-AdvancedSetting -Value 120"

  command = "(Get-VMHost -Name #{input('vmhostName')}) | Get-AdvancedSetting -Name UserVars.ESXiShellInteractiveTimeOut | Select-Object -ExpandProperty Value"
  describe powercli_command(command) do
    its('stdout.strip') { should cmp "120" }
  end

end

