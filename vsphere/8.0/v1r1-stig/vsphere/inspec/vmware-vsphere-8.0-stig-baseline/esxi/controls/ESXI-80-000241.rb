control 'ESXI-80-000241' do
  title 'The ESXi host must not use the default Active Directory ESX Admin group.'
  desc 'When adding ESXi hosts to Active Directory, all user/group accounts assigned to the Active Directory group "ESX Admins" will have full administrative access to the host.

If this group is not controlled or known to the system administrators, it may be used for inappropriate access to the host. Therefore, the default group must be changed to a site-specific Active Directory group and membership must be severely restricted.'
  desc 'check', 'For systems that do not use Active Directory, this is not applicable.

From the vSphere Client, go to Hosts and Clusters.

Select the ESXi Host >> Configure >> System >> Advanced System Settings.

Select the "Config.HostAgent.plugins.hostsvc.esxAdminsGroup" value and verify it is not set to "ESX Admins".

or

From a PowerCLI command prompt while connected to the ESXi host, run the following command:

Get-VMHost | Get-AdvancedSetting -Name Config.HostAgent.plugins.hostsvc.esxAdminsGroup

If the "Config.HostAgent.plugins.hostsvc.esxAdminsGroup" setting is set to "ESX Admins", this is a finding.'
  desc 'fix', 'From the vSphere Client, go to Hosts and Clusters.

Select the ESXi Host >> Configure >> System >> Advanced System Settings.

Click "Edit". Select the "Config.HostAgent.plugins.hostsvc.esxAdminsGroup" key and configure its value to an appropriate Active Directory group other than "ESX Admins".

or

From a PowerCLI command prompt while connected to the ESXi host, run the following command:

Get-VMHost | Get-AdvancedSetting -Name Config.HostAgent.plugins.hostsvc.esxAdminsGroup | Set-AdvancedSetting -Value "<site specific AD group>"

Note: Changing the group name does not remove the permissions of the previous group.'
  impact 0.5
  tag check_id: 'C-62536r933447_chk'
  tag severity: 'medium'
  tag gid: 'V-258796'
  tag rid: 'SV-258796r933449_rule'
  tag stig_id: 'ESXI-80-000241'
  tag gtitle: 'SRG-OS-000480-VMM-002000'
  tag fix_id: 'F-62445r933448_fix'
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']

  vmhostName = input('vmhostName')
  cluster = input('cluster')
  allhosts = input('allesxi')
  vmhosts = []

  unless vmhostName.empty?
    vmhosts = powercli_command("Get-VMHost -Name #{vmhostName} | Sort-Object Name | Select -ExpandProperty Name").stdout.split
  end
  unless cluster.empty?
    vmhosts = powercli_command("Get-Cluster -Name '#{cluster}' | Get-VMHost | Sort-Object Name | Select -ExpandProperty Name").stdout.split
  end
  unless allhosts == false
    vmhosts = powercli_command('Get-VMHost | Sort-Object Name | Select -ExpandProperty Name').stdout.split
  end

  if !vmhosts.empty?
    vmhosts.each do |vmhost|
      command = "Get-VMHost -Name #{vmhost} | Get-VMHostAuthentication | Select-Object -ExpandProperty DomainMembershipStatus"
      domainstatus = powercli_command(command).stdout
      if domainstatus.empty?
        impact 0.0
        describe '' do
          skip "The ESXi host #{vmhost} is not joined to AD, so this control is not applicable."
        end
      else
        command = "Get-VMHost -Name #{vmhost} | Get-AdvancedSetting -Name Config.HostAgent.plugins.hostsvc.esxAdminsGroup | Select-Object -ExpandProperty Value"
        describe powercli_command(command) do
          its('stdout.strip') { should_not cmp 'ESX Admins' }
          its('stdout.strip') { should cmp "#{input('adAdminGroup')}" }
        end
      end
    end
  else
    describe 'No hosts found!' do
      skip 'No hosts found...skipping tests'
    end
  end
end
