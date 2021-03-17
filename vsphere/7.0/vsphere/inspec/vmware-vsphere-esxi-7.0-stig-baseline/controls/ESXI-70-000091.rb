# encoding: UTF-8

control 'ESXI-70-000091' do
  title "The ESXi host must be configured with an appropriate maximum password
age."
  desc  "The older an ESXi local account password is, the larger the
opportunity window is for attackers to guess, crack or re-use a previously
cracked password. Rotating passwords on a regular basis is a fundamental
security practice and one that ESXi supports."
  desc  'rationale', ''
  desc  'check', "
    From the vSphere Client go to Hosts and Clusters >> Select the ESXi Host >>
Configure >> System >> Advanced System Settings. Select the
\"Security.PasswordMaxDays\" value and verify it is set to \"90\".

    or

    From a PowerCLI command prompt while connected to the ESXi host run the
following command:

    Get-VMHost | Get-AdvancedSetting -Name Security.PasswordMaxDays

    If the \"Security.PasswordMaxDays\" setting is not set to \"90\", this is a
finding
  "
  desc  'fix', "
    Fom the vSphere Client go to Hosts and Clusters >> Select the ESXi Host >>
Configure >> System >> Advanced System Settings. Select the
\"Security.PasswordMaxDays\" value and set it to \"90\".

    or

    From a PowerCLI command prompt while connected to the ESXi host run the
following command:

    Get-VMHost | Get-AdvancedSetting -Name Security.PasswordMaxDays |
Set-AdvancedSetting -Value \"90\"
  "
  impact 0.5
  tag severity: 'medium'
  tag gtitle: 'SRG-OS-000480-VMM-002000'
  tag gid: nil
  tag rid: nil
  tag stig_id: 'ESXI-70-000091'
  tag fix_id: nil
  tag cci: 'CCI-000366'
  tag nist: ['CM-6 b']

  command = "(Get-VMHost -Name #{input('vmhostName')}) | Get-AdvancedSetting -Name Security.PasswordMaxDays | Select-Object -ExpandProperty Value"
  describe powercli_command(command) do
    its ('stdout.strip') { should cmp "90" }
  end

end

