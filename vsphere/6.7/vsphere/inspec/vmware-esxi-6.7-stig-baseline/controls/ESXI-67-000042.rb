control "ESXI-67-000042" do
  title "The ESXi host must terminate shell services after ten minutes."
  desc  "When the ESXi Shell or SSH services are enabled on a host they will
run indefinitely.  To avoid having these services left running set the
ESXiShellTimeOut. The ESXiShellTimeOut defines a window of time after which the
ESXi Shell and SSH services will automatically be stopped."
  impact 0.5
  tag severity: "CAT II"
  tag gtitle: "SRG-OS-000163-VMM-000700"
  tag rid: "ESXI-67-000042"
  tag stig_id: "ESXI-67-000042"
  tag cci: "CCI-001133"
  tag nist: ["SC-10", "Rev_4"]
  desc 'check', "From the vSphere Client select the ESXi Host and go to Configure
>> System >> Advanced System Settings. Select the UserVars.ESXiShellTimeOut
value and verify it is set to 600 (10 Minutes).

or

From a PowerCLI command prompt while connected to the ESXi host run the
following command:

Get-VMHost | Get-AdvancedSetting -Name UserVars.ESXiShellTimeOut

If the UserVars.ESXiShellTimeOut setting is not set to 600, this is a finding."
  desc 'fix', "From the vSphere Client select the ESXi Host and go to Configure >>
System >> Advanced System Settings. Click Edit and select the
UserVars.ESXiShellTimeOut value and configure it to 600.

or

From a PowerCLI command prompt while connected to the ESXi host run the
following commands:

Get-VMHost | Get-AdvancedSetting -Name UserVars.ESXiShellTimeOut |
Set-AdvancedSetting -Value 600"

  command = "(Get-VMHost -Name #{input('vmhostName')}) | Get-AdvancedSetting -Name UserVars.ESXiShellTimeOut | Select-Object -ExpandProperty Value"
  describe powercli_command(command) do
    its('stdout.strip') { should cmp "600" }
  end

end

