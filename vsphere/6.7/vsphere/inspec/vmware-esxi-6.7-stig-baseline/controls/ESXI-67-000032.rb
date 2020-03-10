control "ESXI-67-000032" do
  title "The ESXi host must prohibit the reuse of passwords within five
iterations."
  desc  "If a user, or root, used the same password continuously or was allowed
to change it back shortly after being forced to change it to something else, it
would provide a potential intruder with the opportunity to keep guessing at one
user's password until it was guessed correctly."
  impact 0.5
  tag severity: "CAT II"
  tag gtitle: "SRG-OS-000077-VMM-000440"
  tag rid: "ESXI-67-000032"
  tag stig_id: "ESXI-67-000032"
  tag cci: "CCI-000200"
  tag nist: ["IA-5 (1) (e)", "Rev_4"]
  desc 'check', "From the vSphere Client select the ESXi Host and go to Configure
>> System >> Advanced System Settings. Select the Security.PasswordHistory
value and verify it is set to 5.

or

From a PowerCLI command prompt while connected to the ESXi host run the
following command:

Get-VMHost | Get-AdvancedSetting -Name Security.PasswordHistory

If the Security.PasswordHistory setting is not set to 5 this is a finding."
  desc 'fix', "From the vSphere Client select the ESXi Host and go to Configure >>
System >> Advanced System Settings. Select the Security.PasswordHistory value
and configure it to 5.

or

From a PowerCLI command prompt while connected to the ESXi host run the
following command:

Get-VMHost | Get-AdvancedSetting -Name Security.PasswordHistory |
Set-AdvancedSetting -Value 5"

  command = "(Get-VMHost -Name #{input('vmhostName')}) | Get-AdvancedSetting -Name Security.PasswordHistory | Select-Object -ExpandProperty Value"
  describe powercli_command(command) do
    its('stdout.strip') { should match "5" }
  end

end

