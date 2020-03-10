control "ESXI-67-000079" do
  title "The ESXi host must not suppress warnings that the local or remote
shell sessions are enabled."
  desc  "Warnings that local or remote shell sessions are enabled alert
administrators to activity that they may not be aware of and need to
investigate."
  impact 0.5
  tag severity: "CAT II"
  tag gtitle: "SRG-OS-000480-VMM-002000"
  tag rid: "ESXI-67-000079"
  tag stig_id: "ESXI-67-000079"
  tag cci: "CCI-000366"
  tag nist: ["CM-6 b", "Rev_4"]
  desc 'check', "From the vSphere Web Client, select the host and then click
Configure >> System >> Advanced System Settings. Find the
UserVars.SuppressShellWarning value and verify that it is set to the following:

0

If the value is not set as above or it does not exist, this is a finding.

or

From a PowerCLI command prompt while connected to the ESXi host run the
following command:

Get-VMHost | Get-AdvancedSetting -Name UserVars.SuppressShellWarning

If the value returned is not \"0\" or the setting does not exist, this is a
finding."
  desc 'fix', "From the vSphere Web Client, select the host and then click
Configure >> System >> Advanced System Settings. Find the
UserVars.SuppressShellWarning value and set it to the following:

0

or

From a PowerCLI command prompt while connected to the ESXi host run the
following command:

Get-VMHost | Get-AdvancedSetting -Name UserVars.SuppressShellWarning |
Set-AdvancedSetting -Value \"0\""

  command = "(Get-VMHost -Name #{input('vmhostName')}) | Get-AdvancedSetting -Name UserVars.SuppressShellWarning | Select-Object -ExpandProperty Value"
  describe powercli_command(command) do
    its('stdout.strip') { should cmp "0" }
  end

end

