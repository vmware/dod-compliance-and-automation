# encoding: UTF-8

control 'ESXI-70-000079' do
  title "The ESXi host must not suppress warnings that the local or remote
shell sessions are enabled."
  desc  "Warnings that local or remote shell sessions are enabled alert
administrators to activity that they may not be aware of and need to
investigate."
  desc  'rationale', ''
  desc  'check', "
    Fom the vSphere Client go to Hosts and Clusters >> Select the ESXi Host >>
Configure >> System >> Advanced System Settings. Select the
\"UserVars.SuppressShellWarning\" value and verify that it is set to \"0\".

    or

    From a PowerCLI command prompt while connected to the ESXi host run the
following command:

    Get-VMHost | Get-AdvancedSetting -Name UserVars.SuppressShellWarning

    If the \"UserVars.SuppressShellWarning\" setting is not set to \"0\" or the
setting does not exist, this is a finding.
  "
  desc  'fix', "
    Fom the vSphere Client go to Hosts and Clusters >> Select the ESXi Host >>
Configure >> System >> Advanced System Settings. Select the
\"UserVars.SuppressShellWarning\" value and set it to \"0\".

    or

    From a PowerCLI command prompt while connected to the ESXi host run the
following command:

    Get-VMHost | Get-AdvancedSetting -Name UserVars.SuppressShellWarning |
Set-AdvancedSetting -Value \"0\"
  "
  impact 0.5
  tag severity: 'medium'
  tag gtitle: 'SRG-OS-000480-VMM-002000'
  tag gid: nil
  tag rid: nil
  tag stig_id: 'ESXI-70-000079'
  tag fix_id: nil
  tag cci: 'CCI-000366'
  tag nist: ['CM-6 b']

  command = "(Get-VMHost -Name #{input('vmhostName')}) | Get-AdvancedSetting -Name UserVars.SuppressShellWarning | Select-Object -ExpandProperty Value"
  describe powercli_command(command) do
    its ('stdout.strip') { should cmp "0" }
  end

end

