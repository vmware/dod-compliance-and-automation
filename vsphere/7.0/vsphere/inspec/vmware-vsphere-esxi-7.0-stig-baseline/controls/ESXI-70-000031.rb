# encoding: UTF-8

control 'ESXI-70-000031' do
  title "The ESXi host must be configured with a sufficiently complex password
policy."
  desc  "To enforce the use of complex passwords, minimum numbers of characters
of different classes are mandated. The use of complex passwords reduces the
ability of attackers to successfully obtain valid passwords using guessing or
exhaustive search techniques. Complexity requirements increase the password
search space by requiring users to construct passwords from a larger character
set than they may otherwise use."
  desc  'rationale', ''
  desc  'check', "
    From the vSphere Client go to Hosts and Clusters >> Select the ESXi Host >>
Configure >> System >> Advanced System Settings. Select the
\"Security.PasswordQualityControl\" value and verify it is set to
\"similar=deny retry=3 min=disabled,disabled,disabled,disabled,15\"

    or

    From a PowerCLI command prompt while connected to the ESXi host run the
following command:

    Get-VMHost | Get-AdvancedSetting -Name Security.PasswordQualityControl

    If the \"Security.PasswordQualityControl\" setting is not set to
\"similar=deny retry=3 min=disabled,disabled,disabled,disabled,15\", this is a
finding.
  "
  desc  'fix', "
    From the vSphere Client go to Hosts and Clusters >> Select the ESXi Host >>
Configure >> System >> Advanced System Settings. Click \"Edit\". Select the
\"Security.PasswordQualityControl\" value and configure it to \"similar=deny
retry=3 min=disabled,disabled,disabled,disabled,15\".

    or

    From a PowerCLI command prompt while connected to the ESXi host run the
following command(s):

    Get-VMHost | Get-AdvancedSetting -Name Security.PasswordQualityControl |
Set-AdvancedSetting -Value \"similar=deny retry=3
min=disabled,disabled,disabled,disabled,15\"
  "
  impact 0.5
  tag severity: 'medium'
  tag gtitle: 'SRG-OS-000069-VMM-000360'
  tag gid: nil
  tag rid: nil
  tag stig_id: 'ESXI-70-000031'
  tag fix_id: nil
  tag cci: 'CCI-000192'
  tag nist: ['IA-5 (1) (a)']

  command = "(Get-VMHost -Name #{input('vmhostName')}) | Get-AdvancedSetting -Name Security.PasswordQualityControl | Select-Object -ExpandProperty Value"
  describe powercli_command(command) do
    its ('stdout.strip') { should match "similar=deny retry=3 min=disabled,disabled,disabled,disabled,15" }
  end

end

