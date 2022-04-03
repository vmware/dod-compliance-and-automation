control 'ESXI-67-000041' do
  title "The ESXi host must set a timeout to automatically disable idle shell
sessions after two minutes."
  desc  "If a user forgets to log out of their local or remote ESXi Shell
session, the idle connection will remain open indefinitely and increase the
likelihood of inappropriate host access via session hijacking. The
\"ESXiShellInteractiveTimeOut\" allows the automatic termination of idle shell
sessions.
  "
  desc  'rationale', ''
  desc  'check', "
    From the vSphere Client, select the ESXi host and go to Configure >> System
>> Advanced System Settings.

    Select the \"UserVars.ESXiShellInteractiveTimeOut\" value and verify it is
set to \"120\" (2 Minutes).

    or

    From a PowerCLI command prompt while connected to the ESXi host, run the
following command:

    Get-VMHost | Get-AdvancedSetting -Name UserVars.ESXiShellInteractiveTimeOut

    If the \"UserVars.ESXiShellInteractiveTimeOut\" setting is not set to
\"120\", this is a finding.
  "
  desc 'fix', "
    From the vSphere Client, select the ESXi Host and go to Configure >> System
>> Advanced System Settings.

    Click \"Edit\", select the \"UserVars.ESXiShellInteractiveTimeOut\" value,
and configure it to \"120\".

    or

    From a PowerCLI command prompt while connected to the ESXi host, run the
following commands:

    Get-VMHost | Get-AdvancedSetting -Name UserVars.ESXiShellInteractiveTimeOut
| Set-AdvancedSetting -Value 120
  "
  impact 0.5
  tag severity: 'medium'
  tag gtitle: 'SRG-OS-000163-VMM-000700'
  tag satisfies: ['SRG-OS-000163-VMM-000700', 'SRG-OS-000279-VMM-001010']
  tag gid: 'V-239296'
  tag rid: 'SV-239296r674817_rule'
  tag stig_id: 'ESXI-67-000041'
  tag fix_id: 'F-42488r674816_fix'
  tag cci: ['CCI-001133', 'CCI-002361']
  tag nist: ['SC-10', 'AC-12']

  command = "(Get-VMHost -Name #{input('vmhostName')}) | Get-AdvancedSetting -Name UserVars.ESXiShellInteractiveTimeOut | Select-Object -ExpandProperty Value"
  describe powercli_command(command) do
    its('stdout.strip') { should cmp '120' }
  end
end
