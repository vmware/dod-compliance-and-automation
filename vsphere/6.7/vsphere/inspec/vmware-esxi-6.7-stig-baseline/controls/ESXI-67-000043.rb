control "ESXI-67-000043" do
  title "The ESXi host must logout of the console UI after two minutes."
  desc  "When the Direct console user interface (DCUI) is enabled and logged in
it should be automatically logged out if left logged in to avoid access by
unauthorized persons.  The DcuiTimeOut setting defines a window of time after
which the DCUI will be logged out."
  impact 0.5
  tag severity: "CAT II"
  tag gtitle: "SRG-OS-000163-VMM-000700"
  tag rid: "ESXI-67-000043"
  tag stig_id: "ESXI-67-000043"
  tag cci: "CCI-001133"
  tag nist: ["SC-10", "Rev_4"]
  desc 'check', "From the vSphere Client select the ESXi Host and go to Configure
>> System >> Advanced System Settings. Select the UserVars.DcuiTimeOut value
and verify it is set to 120 (2 Minutes).

or

From a PowerCLI command prompt while connected to the ESXi host run the
following command:

Get-VMHost | Get-AdvancedSetting -Name UserVars.DcuiTimeOut

If the UserVars.DcuiTimeOut setting is not set to 120, this is a finding."
  desc 'fix', "From the vSphere Client select the ESXi Host and go to Configure >>
System >> Advanced System Settings. Click Edit and select the
UserVars.DcuiTimeOut value and configure it to 120.

or

From a PowerCLI command prompt while connected to the ESXi host run the
following commands:

Get-VMHost | Get-AdvancedSetting -Name UserVars.DcuiTimeOut |
Set-AdvancedSetting -Value 120"

  command = "(Get-VMHost -Name #{input('vmhostName')}) | Get-AdvancedSetting -Name UserVars.DcuiTimeOut | Select-Object -ExpandProperty Value"
  describe powercli_command(command) do
    its('stdout.strip') { should cmp "120" }
  end

end

