control 'VCFE-9X-000010' do
  title 'The ESX host client must be configured with an idle session timeout.'
  desc  'The ESX host client is the UI served up by the host itself, outside of vCenter. ESX is not usually administered via this interface for long periods, and all users will be highly privileged. Implementing a mandatory session idle limit will ensure that orphaned, forgotten, or ignored sessions will be closed promptly.'
  desc  'rationale', ''
  desc  'check', "
    From the vSphere Client, go to Hosts and Clusters.

    Select the ESX Host >> Configure >> System >> Advanced System Settings.

    Select the \"UserVars.HostClientSessionTimeout\" value and verify it is set to \"900\" or less.

    or

    From a PowerCLI command prompt while connected to the ESX host, run the following command:

    Get-VMHost | Get-AdvancedSetting -Name UserVars.HostClientSessionTimeout

    If the \"UserVars.HostClientSessionTimeout\" setting is not set to \"900\" or less, this is a finding.
  "
  desc 'fix', "
    From the vSphere Client, go to Hosts and Clusters.

    Select the ESX Host >> Configure >> System >> Advanced System Settings.

    Click \"Edit\". Select the \"UserVars.HostClientSessionTimeout\" value and configure it to \"900\".

    or

    From a PowerCLI command prompt while connected to the ESX host, run the following command:

    Get-VMHost | Get-AdvancedSetting -Name UserVars.HostClientSessionTimeout | Set-AdvancedSetting -Value \"900\"
  "
  impact 0.5
  tag severity: 'medium'
  tag gtitle: 'SRG-OS-000029-VMM-000100'
  tag gid: 'V-VCFE-9X-000010'
  tag rid: 'SV-VCFE-9X-000010'
  tag stig_id: 'VCFE-9X-000010'
  tag cci: ['CCI-000057']
  tag nist: ['AC-11 a']

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
      command = "Get-VMHost -Name #{vmhost} | Get-AdvancedSetting -Name UserVars.HostClientSessionTimeout | Select-Object -ExpandProperty Value"
      describe powercli_command(command) do
        its('stdout.strip') { should cmp <= 900 }
      end
    end
  end
end
