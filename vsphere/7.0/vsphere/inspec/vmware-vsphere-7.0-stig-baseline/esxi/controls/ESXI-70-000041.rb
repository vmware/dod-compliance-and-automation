control 'ESXI-70-000041' do
  title 'The ESXi host must set a timeout to automatically disable idle shell sessions after two minutes.'
  desc  'If a user forgets to log out of their local or remote ESXi Shell session, the idle connection will remain open indefinitely and increase the likelihood of inapprioriate host access via session hijacking. The "ESXiShellInteractiveTimeOut" allows the automatic termination of idle shell sessions.'
  desc  'rationale', ''
  desc  'check', "
    From the vSphere Client go to Hosts and Clusters >> Select the ESXi Host >> Configure >> System >> Advanced System Settings.

    Select the \"UserVars.ESXiShellInteractiveTimeOut\" value and verify it is set to \"120\" (2 minutes).

    or

    From a PowerCLI command prompt while connected to the ESXi host, run the following command:

    Get-VMHost | Get-AdvancedSetting -Name UserVars.ESXiShellInteractiveTimeOut

    If the \"UserVars.ESXiShellInteractiveTimeOut\" setting is not set to \"120\", this is a finding.
  "
  desc 'fix', "
    From the vSphere Client go to Hosts and Clusters >> Select the ESXi Host >> Configure >> System >> Advanced System Settings.

    Click \"Edit\". Select the \"UserVars.ESXiShellInteractiveTimeOut\" value and configure it to \"120\".

    or

    From a PowerCLI command prompt while connected to the ESXi host, run the following command(s):

    Get-VMHost | Get-AdvancedSetting -Name UserVars.ESXiShellInteractiveTimeOut | Set-AdvancedSetting -Value 120
  "
  impact 0.5
  tag severity: 'medium'
  tag gtitle: 'SRG-OS-000163-VMM-000700'
  tag satisfies: ['SRG-OS-000279-VMM-001010']
  tag gid: nil
  tag rid: nil
  tag stig_id: 'ESXI-70-000041'
  tag cci: ['CCI-001133', 'CCI-002361']
  tag nist: ['AC-12', 'SC-10']

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
      command = "Get-VMHost -Name #{vmhost} | Get-AdvancedSetting -Name UserVars.ESXiShellInteractiveTimeOut | Select-Object -ExpandProperty Value"
      describe powercli_command(command) do
        its('stdout.strip') { should cmp '120' }
      end
    end
  else
    describe 'No hosts found!' do
      skip 'No hosts found...skipping tests'
    end
  end
end
