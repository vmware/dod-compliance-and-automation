control 'ESXI-70-000039' do
  title 'Active Directory ESX Admin group membership must not be used when adding ESXi hosts to Active Directory.'
  desc 'When adding ESXi hosts to Active Directory, all user/group accounts assigned to the Active Directory group \\"ESX Admins\\" will have full administrative access to the host.

If this group is not controlled or known to the system administrators, it may be used for inappropriate access to the host. Therefore, the default group must be changed to a site-specific Active Directory group and membership must be severely restricted.'
  desc 'check', 'For systems that do not use Active Directory, this is not applicable.

From the vSphere Client, go to Hosts and Clusters.

Select the ESXi Host >> Configure >> System >> Advanced System Settings.

Select the "Config.HostAgent.plugins.hostsvc.esxAdminsGroup" value and verify it is not set to "ESX Admins".

or

From a PowerCLI command prompt while connected to the ESXi host, run the following command:

Get-VMHost | Get-AdvancedSetting -Name Config.HostAgent.plugins.hostsvc.esxAdminsGroup

If the "Config.HostAgent.plugins.hostsvc.esxAdminsGroup" key is set to "ESX Admins", this is a finding.'
  desc 'fix', 'From the vSphere Client, go to Hosts and Clusters.

Select the ESXi Host >> Configure >> System >> Advanced System Settings.

Click "Edit". Select the "Config.HostAgent.plugins.hostsvc.esxAdminsGroup" key and configure its value to an appropriate Active Directory group other than "ESX Admins".

or

From a PowerCLI command prompt while connected to the ESXi host, run the following command:

Get-VMHost | Get-AdvancedSetting -Name Config.HostAgent.plugins.hostsvc.esxAdminsGroup | Set-AdvancedSetting -Value <AD Group>'
  impact 0.5
  tag check_id: 'C-60079r885991_chk'
  tag severity: 'medium'
  tag gid: 'V-256404'
  tag rid: 'SV-256404r885993_rule'
  tag stig_id: 'ESXI-70-000039'
  tag gtitle: 'SRG-OS-000104-VMM-000500'
  tag fix_id: 'F-60022r885992_fix'
  tag cci: ['CCI-000764']
  tag nist: ['IA-2']

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
      command = "Get-VMHost -Name #{vmhost} | Get-AdvancedSetting -Name Config.HostAgent.plugins.hostsvc.esxAdminsGroup | Select-Object -ExpandProperty Value"
      describe powercli_command(command) do
        its('stdout.strip') { should_not cmp 'ESX Admins' }
        its('stdout.strip') { should cmp "#{input('adAdminGroup')}" }
      end
    end
  else
    describe 'No hosts found!' do
      skip 'No hosts found...skipping tests'
    end
  end
end
