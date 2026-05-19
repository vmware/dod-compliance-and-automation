control 'VCFE-9X-000066' do
  title 'The ESX host must set a timeout to automatically end idle shell sessions after fifteen minutes.'
  desc  'If a user forgets to log out of their local or remote ESX Shell session, the idle connection will remain open indefinitely and increase the likelihood of inappropriate host access via session hijacking. The "ESXiShellInteractiveTimeOut" allows the automatic termination of idle shell sessions.'
  desc  'rationale', ''
  desc  'check', "
    From the vSphere Client, go to Hosts and Clusters.

    Select the ESX Host >> Configure >> System >> Advanced System Settings.

    Select the \"UserVars.ESXiShellInteractiveTimeOut\" value and verify it is set to \"900\" or less and not \"0\".

    or

    From a PowerCLI command prompt while connected to the ESX host, run the following command:

    Get-VMHost | Get-AdvancedSetting -Name UserVars.ESXiShellInteractiveTimeOut

    If the \"UserVars.ESXiShellInteractiveTimeOut\" setting is set to a value greater than \"900\" or \"0\", this is a finding.
  "
  desc 'fix', "
    From the vSphere Client, go to Hosts and Clusters.

    Select the ESX Host >> Configure >> System >> Advanced System Settings.

    Click \"Edit\". Select the \"UserVars.ESXiShellInteractiveTimeOut\" value and configure it to \"900\".

    or

    From a PowerCLI command prompt while connected to the ESX host, run the following command:

    Get-VMHost | Get-AdvancedSetting -Name UserVars.ESXiShellInteractiveTimeOut | Set-AdvancedSetting -Value 900
  "
  impact 0.5
  tag severity: 'medium'
  tag gtitle: 'SRG-OS-000163-VMM-000700'
  tag satisfies: ['SRG-OS-000279-VMM-001010']
  tag gid: 'V-VCFE-9X-000066'
  tag rid: 'SV-VCFE-9X-000066'
  tag stig_id: 'VCFE-9X-000066'
  tag cci: ['CCI-001133', 'CCI-002361']
  tag nist: ['AC-12', 'SC-10']

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
      command = "Get-VMHost -Name #{vmhost} | Get-AdvancedSetting -Name UserVars.ESXiShellInteractiveTimeOut | Select-Object -ExpandProperty Value"
      describe powercli_command(command) do
        its('stdout.strip') { should cmp <= 900 }
        its('stdout.strip') { should_not cmp 0 }
      end
    end
  end
end
