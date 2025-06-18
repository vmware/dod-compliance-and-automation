control 'VCFE-9X-000201' do
  title 'The ESX host must set a timeout to automatically end idle DCUI sessions after 10 minutes.'
  desc  'When the Direct Console User Interface (DCUI) is enabled and logged in, it should be automatically logged out if left logged on to avoid access by unauthorized persons. The "DcuiTimeOut" setting defines a window of time after which the DCUI will be logged out.'
  desc  'rationale', ''
  desc  'check', "
    From the vSphere Client, go to Hosts and Clusters.

    Select the ESX Host >> Configure >> System >> Advanced System Settings.

    Select the \"UserVars.DcuiTimeOut\" value and verify it is set to \"600\" or less and not \"0\".

    or

    From a PowerCLI command prompt while connected to the ESX host, run the following command:

    Get-VMHost | Get-AdvancedSetting -Name UserVars.DcuiTimeOut

    If the \"UserVars.DcuiTimeOut\" setting is set to a value greater than \"600\" or is set to \"0\", this is a finding.
  "
  desc 'fix', "
    From the vSphere Client, go to Hosts and Clusters.

    Select the ESX Host >> Configure >> System >> Advanced System Settings.

    Click \"Edit\". Select the \"UserVars.DcuiTimeOut\" value and configure it to \"600\".

    or

    From a PowerCLI command prompt while connected to the ESX host, run the following command:

    Get-VMHost | Get-AdvancedSetting -Name UserVars.DcuiTimeOut | Set-AdvancedSetting -Value 600
  "
  impact 0.5
  tag severity: 'medium'
  tag gtitle: 'SRG-OS-000163-VMM-000700'
  tag gid: 'V-VCFE-9X-000201'
  tag rid: 'SV-VCFE-9X-000201'
  tag stig_id: 'VCFE-9X-000201'
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
      command = "Get-VMHost -Name #{vmhost} | Get-AdvancedSetting -Name UserVars.DcuiTimeOut | Select-Object -ExpandProperty Value"
      describe powercli_command(command) do
        its('stdout.strip') { should cmp <= 600 }
        its('stdout.strip') { should_not cmp 0 }
      end
    end
  end
end
