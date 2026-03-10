control 'VCFE-9X-000200' do
  title 'The ESX host must automatically stop shell services after ten minutes.'
  desc  'When the ESX Shell or Secure Shell (SSH) services are enabled on a host, they will run indefinitely. To avoid having these services left running, set the "ESXiShellTimeOut". The "ESXiShellTimeOut" defines a window of time after which the ESX Shell and SSH services will be stopped automatically.'
  desc  'rationale', ''
  desc  'check', "
    From the vSphere Client, go to Hosts and Clusters.

    Select the ESX Host >> Configure >> System >> Advanced System Settings.

    Select the \"UserVars.ESXiShellTimeOut\" value and verify it is set to \"600\" or less and not \"0\".

    or

    From a PowerCLI command prompt while connected to the ESX host, run the following command:

    Get-VMHost | Get-AdvancedSetting -Name UserVars.ESXiShellTimeOut

    If the \"UserVars.ESXiShellTimeOut\" setting is set to a value greater than \"600\" or \"0\", this is a finding.
  "
  desc 'fix', "
    From the vSphere Client, go to Hosts and Clusters.

    Select the ESX Host >> Configure >> System >> Advanced System Settings.

    Click \"Edit\". Select the \"UserVars.ESXiShellTimeOut\" value and configure it to \"600\".

    or

    From a PowerCLI command prompt while connected to the ESX host, run the following command:

    Get-VMHost | Get-AdvancedSetting -Name UserVars.ESXiShellTimeOut | Set-AdvancedSetting -Value 600
  "
  impact 0.5
  tag severity: 'medium'
  tag gtitle: 'SRG-OS-000163-VMM-000700'
  tag gid: 'V-VCFE-9X-000200'
  tag rid: 'SV-VCFE-9X-000200'
  tag stig_id: 'VCFE-9X-000200'
  tag cci: ['CCI-001133']
  tag nist: ['SC-10']

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
      command = "Get-VMHost -Name #{vmhost} | Get-AdvancedSetting -Name UserVars.ESXiShellTimeOut | Select-Object -ExpandProperty Value"
      describe powercli_command(command) do
        its('stdout.strip') { should cmp <= 600 }
        its('stdout.strip') { should_not cmp 0 }
      end
    end
  end
end
