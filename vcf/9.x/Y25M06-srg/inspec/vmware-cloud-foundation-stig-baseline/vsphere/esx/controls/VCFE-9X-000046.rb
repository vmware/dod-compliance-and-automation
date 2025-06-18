control 'VCFE-9X-000046' do
  title 'The ESX host must be configured to disable nonessential capabilities by disabling the Managed Object Browser (MOB).'
  desc  'The MOB provides a way to explore the object model used by the VMkernel to manage the host and enables configurations to be changed. This interface is meant to be used primarily for debugging the vSphere Software Development Kit (SDK), but because there are no access controls it could also be used as a method to obtain information about a host being targeted for unauthorized access.'
  desc  'rationale', ''
  desc  'check', "
    From the vSphere Client, go to Hosts and Clusters.

    Select the ESX Host >> Configure >> System >> Advanced System Settings.

    Select the \"Config.HostAgent.plugins.solo.enableMob\" value and verify it is set to \"false\".

    or

    From a PowerCLI command prompt while connected to the ESX host, run the following command:

    Get-VMHost | Get-AdvancedSetting -Name Config.HostAgent.plugins.solo.enableMob

    If the \"Config.HostAgent.plugins.solo.enableMob\" setting is not set to \"false\", this is a finding.
  "
  desc 'fix', "
    From the vSphere Client, go to Hosts and Clusters.

    Select the ESX Host >> Configure >> System >> Advanced System Settings.

    Click \"Edit\". Select the \"Config.HostAgent.plugins.solo.enableMob\" value and configure it to \"false\".

    or

    From a PowerCLI command prompt while connected to the ESX host, run the following command:

    Get-VMHost | Get-AdvancedSetting -Name Config.HostAgent.plugins.solo.enableMob | Set-AdvancedSetting -Value false
  "
  impact 0.5
  tag severity: 'medium'
  tag gtitle: 'SRG-OS-000095-VMM-000480'
  tag gid: 'V-VCFE-9X-000046'
  tag rid: 'SV-VCFE-9X-000046'
  tag stig_id: 'VCFE-9X-000046'
  tag cci: ['CCI-000381']
  tag nist: ['CM-7 a']

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
      command = "Get-VMHost -Name #{vmhost} | Get-AdvancedSetting -Name Config.HostAgent.plugins.solo.enableMob | Select-Object -ExpandProperty Value"
      describe powercli_command(command) do
        its('stdout.strip') { should cmp 'false' }
      end
    end
  end
end
