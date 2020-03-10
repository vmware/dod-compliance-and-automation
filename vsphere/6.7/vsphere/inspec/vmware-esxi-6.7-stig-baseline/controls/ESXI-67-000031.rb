control "ESXI-67-000031" do
  title "The ESXi host  must enforce password complexity by requiring that at
least one upper-case character be used."
  desc  "To enforce the use of complex passwords, minimum numbers of characters
of different classes are mandated. The use of complex passwords reduces the
ability of attackers to successfully obtain valid passwords using guessing or
exhaustive search techniques. Complexity requirements increase the password
search space by requiring users to construct passwords from a larger character
set than they may otherwise use."
  impact 0.5
  tag severity: "CAT II"
  tag gtitle: "SRG-OS-000069-VMM-000360"
  tag rid: "ESXI-67-000031"
  tag stig_id: "ESXI-67-000031"
  tag cci: "CCI-000192"
  tag nist: ["IA-5 (1) (a)", "Rev_4"]
  desc 'check', "From the vSphere Client select the ESXi Host and go to Configure
>> System >> Advanced System Settings. Select the
Security.PasswordQualityControl value and verify it is set to \"similar=deny
retry=3 min=disabled,disabled,disabled,disabled,15\"

or

From a PowerCLI command prompt while connected to the ESXi host run the
following command:

Get-VMHost | Get-AdvancedSetting -Name Security.PasswordQualityControl

If the Security.PasswordQualityControl setting is not set to \"similar=deny
retry=3 min=disabled,disabled,disabled,disabled,15\", this is a finding."
  desc 'fix', "From the vSphere Client select the ESXi Host and go to Configure >>
System >> Advanced System Settings. Click Edit and select the
Security.PasswordQualityControl value and configure it to \"similar=deny
retry=3 min=disabled,disabled,disabled,disabled,15\".

or

From a PowerCLI command prompt while connected to the ESXi host run the
following commands:

Get-VMHost | Get-AdvancedSetting -Name Security.PasswordQualityControl |
Set-AdvancedSetting -Value \"similar=deny retry=3
min=disabled,disabled,disabled,disabled,15\""

  command = "(Get-VMHost -Name #{input('vmhostName')}) | Get-AdvancedSetting -Name Security.PasswordQualityControl | Select-Object -ExpandProperty Value"
  describe powercli_command(command) do
    its('stdout.strip') { should match "similar=deny retry=3 min=disabled,disabled,disabled,disabled,15" }
  end

end

