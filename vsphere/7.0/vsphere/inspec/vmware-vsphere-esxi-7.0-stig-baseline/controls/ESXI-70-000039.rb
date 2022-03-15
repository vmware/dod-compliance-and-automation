control 'ESXI-70-000039' do
  title "Active Directory ESX Admin group membership must not be used when
adding ESXi hosts to Active Directory."
  desc  "When adding ESXi hosts to Active Directory, all user/group accounts
assigned to the AD group \"ESX Admins\" will have full administrative access to
the host. If this group is not controlled or known to the system administrators
it may be used for inapprioriate access to the host. Therefore, the default
group must be changed to site specific AD group and membership therein must be
severely restricted."
  desc  'rationale', ''
  desc  'check', "
    From the vSphere Client go to Hosts and Clusters >> Select the ESXi Host >>
Configure >> System >> Advanced System Settings. Select the
\"Config.HostAgent.plugins.hostsvc.esxAdminsGroup\" value and verify it is not
set to \"ESX Admins\".

    or

    From a PowerCLI command prompt while connected to the ESXi host run the
following command:

    Get-VMHost | Get-AdvancedSetting -Name
Config.HostAgent.plugins.hostsvc.esxAdminsGroup

    For systems that do not use Active Directory, this is not applicable.

    If the \"Config.HostAgent.plugins.hostsvc.esxAdminsGroup\" key is set to
\"ESX Admins\", this is a finding.
  "
  desc 'fix', "
    From the vSphere Client go to Hosts and Clusters >> Select the ESXi Host >>
Configure >> System >> Advanced System Settings. Click \"Edit\". Select the
\"Config.HostAgent.plugins.hostsvc.esxAdminsGroup\" key and configure it's
value to an appropriate Active Directory group other than \"ESX Admins\".

    or

    From a PowerCLI command prompt while connected to the ESXi host run the
following command(s):

    Get-VMHost | Get-AdvancedSetting -Name
Config.HostAgent.plugins.hostsvc.esxAdminsGroup | Set-AdvancedSetting -Value
<AD Group>
  "
  impact 0.3
  tag severity: 'low'
  tag gtitle: 'SRG-OS-000104-VMM-000500'
  tag gid: nil
  tag rid: nil
  tag stig_id: 'ESXI-70-000039'
  tag fix_id: nil
  tag cci: 'CCI-000764'
  tag nist: ['IA-2']

  command = "(Get-VMHost -Name #{input('vmhostName')}) | Get-AdvancedSetting -Name Config.HostAgent.plugins.hostsvc.esxAdminsGroup | Select-Object -ExpandProperty Value"
  describe powercli_command(command) do
    its('stdout.strip') { should_not cmp 'ESX Admins' }
    its('stdout.strip') { should cmp "#{input('adAdminGroup')}" }
  end
end
