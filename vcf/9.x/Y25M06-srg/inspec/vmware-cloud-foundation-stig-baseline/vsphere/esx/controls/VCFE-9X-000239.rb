control 'VCFE-9X-000239' do
  title 'The ESX host must not use the default Active Directory ESX Admin group.'
  desc  "
    When adding ESX hosts to Active Directory, all user/group accounts assigned to the Active Directory group \"ESX Admins\" will have full administrative access to the host.

    If this group is not controlled or known to the system administrators, it may be used for inappropriate access to the host. Therefore, the default group must be changed to a site-specific Active Directory group and membership must be severely restricted.
  "
  desc  'rationale', ''
  desc  'check', "
    From the vSphere Client, go to Hosts and Clusters.

    Select the ESX Host >> Configure >> System >> Advanced System Settings.

    Select the \"Config.HostAgent.plugins.hostsvc.esxAdminsGroup\" value and verify it is not set to \"ESX Admins\".

    or

    From a PowerCLI command prompt while connected to the ESX host, run the following command:

    Get-VMHost | Get-AdvancedSetting -Name Config.HostAgent.plugins.hostsvc.esxAdminsGroup

    For ESX hosts that are joined to Active Directory, if the \"Config.HostAgent.plugins.hostsvc.esxAdminsGroup\" setting is set to \"ESX Admins\", this is a finding.

    For ESX hosts that are not joined to Active Directory, if the \"Config.HostAgent.plugins.hostsvc.esxAdminsGroup\" setting is not set to \"\", this is a finding.
  "
  desc  'fix', "
    For ESX hosts that are joined to Active Directory, perform the following steps:

    From the vSphere Client, go to Hosts and Clusters.

    Select the ESX Host >> Configure >> System >> Advanced System Settings.

    Click \"Edit\". Select the \"Config.HostAgent.plugins.hostsvc.esxAdminsGroup\" key and configure its value to an appropriate Active Directory group other than \"ESX Admins\".

    or

    From a PowerCLI command prompt while connected to the ESX host, run the following command:

    Get-VMHost | Get-AdvancedSetting -Name Config.HostAgent.plugins.hostsvc.esxAdminsGroup | Set-AdvancedSetting -Value \"<site specific AD group>\"

    For ESX hosts that are NOT joined to Active Directory, perform the following steps:

    From the vSphere Client, go to Hosts and Clusters.

    Select the ESX Host >> Configure >> System >> Advanced System Settings.

    Click \"Edit\". Select the \"Config.HostAgent.plugins.hostsvc.esxAdminsGroup\" key and remove any value present.

    or

    From a PowerCLI command prompt while connected to the ESX host, run the following command:

    Get-VMHost | Get-AdvancedSetting -Name Config.HostAgent.plugins.hostsvc.esxAdminsGroup | Set-AdvancedSetting -Value \"\"
  "
  impact 0.5
  tag severity: 'medium'
  tag gtitle: 'SRG-OS-000480-VMM-002000'
  tag gid: 'V-VCFE-9X-000239'
  tag rid: 'SV-VCFE-9X-000239'
  tag stig_id: 'VCFE-9X-000239'
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']

  vmhostName = input('esx_vmhostName')
  cluster = input('esx_cluster')
  allhosts = input('esx_allHosts')
  vmhosts = []

  unless vmhostName.blank?
    vmhosts = powercli_command("Get-VMHost -Name #{vmhostName} | Sort-Object Name | Select -ExpandProperty Name").stdout.gsub("\r\n", "\n").split("\n")
  end
  unless cluster.blank?
    vmhosts = powercli_command("Get-Cluster -Name '#{cluster}' | Get-VMHost | Sort-Object Name | Select -ExpandProperty Name").stdout.gsub("\r\n", "\n").split("\n")
  end
  unless allhosts == false
    vmhosts = powercli_command('Get-VMHost | Sort-Object Name | Select -ExpandProperty Name').stdout.gsub("\r\n", "\n").split("\n")
  end

  if vmhosts.blank?
    describe 'No ESX hosts found by name or in target vCenter...skipping test. Troubleshoot issue and rerun scan.' do
      skip 'No ESX hosts found by name or in target vCenter...skipping test. Troubleshoot issue and rerun scan.'
    end
  else
    vmhosts.each do |vmhost|
      command = "Get-VMHost -Name #{vmhost} | Get-VMHostAuthentication | Select-Object -ExpandProperty DomainMembershipStatus"
      domainstatus = powercli_command(command).stdout
      command = "Get-VMHost -Name #{vmhost} | Get-AdvancedSetting -Name Config.HostAgent.plugins.hostsvc.esxAdminsGroup | Select-Object -ExpandProperty Value"
      if domainstatus.blank?
        describe powercli_command(command) do
          its('stdout.strip') { should cmp '' }
        end
      else
        describe powercli_command(command) do
          its('stdout.strip') { should_not cmp 'ESX Admins' }
        end
      end
    end
  end
end
