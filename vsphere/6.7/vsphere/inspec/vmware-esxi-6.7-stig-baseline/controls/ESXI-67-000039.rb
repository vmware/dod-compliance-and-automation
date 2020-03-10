control "ESXI-67-000039" do
  title "Active Directory ESX Admin group membership must not be used when
adding ESXi hosts to Active Directory."
  desc  "When adding ESXi hosts to Active Directory, all user/group accounts
assigned to the AD group \"ESX Admins\" will have full administrative access to
the host. If this group is not controlled or known to the system administrators
it may be used for inapprioriate access to the host.  Therefore, the default
group must be changed to site specific AD group and membership therein must be
severely restricted."
  impact 0.3
  tag severity: "CAT III"
  tag gtitle: "SRG-OS-000104-VMM-000500"
  tag rid: "ESXI-67-000039"
  tag stig_id: "ESXI-67-000039"
  tag cci: "CCI-000764"
  tag nist: ["IA-2", "Rev_4"]
  desc 'check', "From the vSphere Client select the ESXi Host and go to
Configuration >> System >> Advanced System Settings. Click Edit and select the
Config.HostAgent.plugins.hostsvc.esxAdminsGroup value and verify it is not set
to \"ESX Admins\".

or

From a PowerCLI command prompt while connected to the ESXi host run the
following command:

Get-VMHost | Get-AdvancedSetting -Name
Config.HostAgent.plugins.hostsvc.esxAdminsGroup

For systems that do not use Active Directory, this is not applicable.

If the \"Config.HostAgent.plugins.hostsvc.esxAdminsGroup\" key is set to \"ESX
Admins\", this is a finding."
  desc 'fix', "From the vSphere Client select the ESXi Host and go to
Configuration >> System >> Advanced System Settings. Click Edit and select the
Config.HostAgent.plugins.hostsvc.esxAdminsGroup key and configure it's value to
an appropriate Active Directory group other than \"ESX Admins\".

or

From a PowerCLI command prompt while connected to the ESXi host run the
following commands:

Get-VMHost | Get-AdvancedSetting -Name
Config.HostAgent.plugins.hostsvc.esxAdminsGroup | Set-AdvancedSetting -Value
<AD Group>"

  command = "(Get-VMHost -Name #{input('vmhostName')}) | Get-AdvancedSetting -Name Config.HostAgent.plugins.hostsvc.esxAdminsGroup | Select-Object -ExpandProperty Value"
  describe powercli_command(command) do
    its('stdout.strip') { should_not cmp "ESX Admins" }
  end

end

