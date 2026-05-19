control 'VCFE-9X-000241' do
  title 'The ESX host must not disable validation of users and groups.'
  desc  'When joined to Active Directory, ESX will periodically validate group membership for any groups with permissions to the host. This process ensures any changes made to groups in Active Directory are synced to ESX and must not be disabled.'
  desc  'rationale', ''
  desc  'check', "
    From the vSphere Client, go to Hosts and Clusters.

    Select the ESX Host >> Configure >> System >> Advanced System Settings.

    Select the \"Config.HostAgent.plugins.vimsvc.authValidateInterval\" value and verify it is not set to \"0\" and is not greater than \"90\".

    or

    From a PowerCLI command prompt while connected to the ESX host, run the following command:

    Get-VMHost | Get-AdvancedSetting -Name Config.HostAgent.plugins.vimsvc.authValidateInterval

    If the \"Config.HostAgent.plugins.vimsvc.authValidateInterval\" setting is set to \"0\", this is a finding.

    If the \"Config.HostAgent.plugins.vimsvc.authValidateInterval\" setting is set to greater than \"90\", this is a finding.
  "
  desc 'fix', "
    From the vSphere Client, go to Hosts and Clusters.

    Select the ESX Host >> Configure >> System >> Advanced System Settings.

    Click \"Edit\". Select the \"Config.HostAgent.plugins.vimsvc.authValidateInterval\" key and configure its value to \"90\".

    or

    From a PowerCLI command prompt while connected to the ESX host, run the following command:

    Get-VMHost | Get-AdvancedSetting -Name Config.HostAgent.plugins.vimsvc.authValidateInterval | Set-AdvancedSetting -Value \"90\"
  "
  impact 0.5
  tag severity: 'medium'
  tag gtitle: 'SRG-OS-000480-VMM-002000'
  tag gid: 'V-VCFE-9X-000241'
  tag rid: 'SV-VCFE-9X-000241'
  tag stig_id: 'VCFE-9X-000241'
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
      command = "Get-VMHost -Name #{vmhost} | Get-AdvancedSetting -Name Config.HostAgent.plugins.vimsvc.authValidateInterval | Select-Object -ExpandProperty Value"
      describe powercli_command(command) do
        its('stdout.strip') { should cmp <= 90 }
        its('stdout.strip') { should cmp > 0 }
      end
    end
  end
end
