control 'ESXI-67-000039' do
  title "Active Directory ESX Admin group membership must not be used when
adding ESXi hosts to Active Directory."
  desc  "When adding ESXi hosts to Active Directory (AD), all user/group
accounts assigned to the AD group \"ESX Admins\" will have full administrative
access to the host. If this group is not controlled or known to the System
Administrators, it may be used for inappropriate access to the host. Therefore,
the default group must be changed to a site-specific AD group and membership
therein must be severely restricted.
  "
  desc  'rationale', ''
  desc  'check', "
    From the vSphere Client, select the ESXi host and go to Configuration >>
System >> Advanced System Settings.

    Click \"Edit\" and select the
\"Config.HostAgent.plugins.hostsvc.esxAdminsGroup\" value and verify it is not
set to \"ESX Admins\".

    or

    From a PowerCLI command prompt while connected to the ESXi host, run the
following command:

    Get-VMHost | Get-AdvancedSetting -Name
Config.HostAgent.plugins.hostsvc.esxAdminsGroup

    For systems that do not use Active Directory, this is Not Applicable.

    If the \"Config.HostAgent.plugins.hostsvc.esxAdminsGroup\" key is set to
\"ESX Admins\", this is a finding.
  "
  desc 'fix', "
    From the vSphere Client, select the ESXi host and go to Configuration >>
System >> Advanced System Settings.

    Click \"Edit\" and select the
\"Config.HostAgent.plugins.hostsvc.esxAdminsGroup\" key and configure its value
to an appropriate Active Directory group other than \"ESX Admins\".

    or

    From a PowerCLI command prompt while connected to the ESXi host, run the
following commands:

    Get-VMHost | Get-AdvancedSetting -Name
Config.HostAgent.plugins.hostsvc.esxAdminsGroup | Set-AdvancedSetting -Value
<AD Group>
  "
  impact 0.3
  tag severity: 'low'
  tag gtitle: 'SRG-OS-000104-VMM-000500'
  tag satisfies: ['SRG-OS-000104-VMM-000500', 'SRG-OS-000109-VMM-000550',
'SRG-OS-000112-VMM-000560', 'SRG-OS-000113-VMM-000570']
  tag gid: 'V-239294'
  tag rid: 'SV-239294r674811_rule'
  tag stig_id: 'ESXI-67-000039'
  tag fix_id: 'F-42486r674810_fix'
  tag cci: ['CCI-000764', 'CCI-000770', 'CCI-001941', 'CCI-001942']
  tag nist: ['IA-2', 'IA-2 (5)', 'IA-2 (8)', 'IA-2 (9)']

  command = "(Get-VMHost -Name #{input('vmhostName')}) | Get-AdvancedSetting -Name Config.HostAgent.plugins.hostsvc.esxAdminsGroup | Select-Object -ExpandProperty Value"
  describe powercli_command(command) do
    its('stdout.strip') { should_not cmp 'ESX Admins' }
  end
end
