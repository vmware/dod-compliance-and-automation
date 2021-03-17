# encoding: UTF-8

control 'ESXI-70-000041' do
  title "The ESXi host must set a timeout to automatically disable idle shell
sessions after two minutes."
  desc  "If a user forgets to log out of their local or remote ESXi Shell
session, the idle connection will remain open indefinitely and increase the
likelyhood of inapprioriate host access via session hijacking. The
ESXiShellInteractiveTimeOut allows you to automatically terminate idle shell
sessions."
  desc  'rationale', ''
  desc  'check', "
    From the vSphere Client go to Hosts and Clusters >> Select the ESXi Host >>
Configure >> System >> Advanced System Settings. Select the
\"UserVars.ESXiShellInteractiveTimeOut\" value and verify it is set to \"120\"
(2 minutes).

    or

    From a PowerCLI command prompt while connected to the ESXi host run the
following command:

    Get-VMHost | Get-AdvancedSetting -Name UserVars.ESXiShellInteractiveTimeOut

    If the \"UserVars.ESXiShellInteractiveTimeOut\" setting is not set to
\"120\", this is a finding.
  "
  desc  'fix', "
    From the vSphere Client go to Hosts and Clusters >> Select the ESXi Host >>
Configure >> System >> Advanced System Settings. Click \"Edit\". Select the
\"UserVars.ESXiShellInteractiveTimeOut\" value and configure it to \"120\".

    or

    From a PowerCLI command prompt while connected to the ESXi host run the
following command(s):

    Get-VMHost | Get-AdvancedSetting -Name UserVars.ESXiShellInteractiveTimeOut
| Set-AdvancedSetting -Value 120
  "
  impact 0.5
  tag severity: 'medium'
  tag gtitle: 'SRG-OS-000163-VMM-000700'
  tag gid: nil
  tag rid: nil
  tag stig_id: 'ESXI-70-000041'
  tag fix_id: nil
  tag cci: 'CCI-001133'
  tag nist: ['SC-10']

  command = "(Get-VMHost -Name #{input('vmhostName')}) | Get-AdvancedSetting -Name UserVars.ESXiShellInteractiveTimeOut | Select-Object -ExpandProperty Value"
  describe powercli_command(command) do
    its ('stdout.strip') { should cmp "120" }
  end

end

