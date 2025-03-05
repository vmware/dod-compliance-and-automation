control 'ESXI-80-000068' do
  title 'The ESXi host must set a timeout to automatically end idle shell sessions after fifteen minutes.'
  desc 'If a user forgets to log out of their local or remote ESXi Shell session, the idle connection will remain open indefinitely and increase the likelihood of inappropriate host access via session hijacking. The "ESXiShellInteractiveTimeOut" allows the automatic termination of idle shell sessions.'
  desc 'check', 'From the vSphere Client, go to Hosts and Clusters.

Select the ESXi Host >> Configure >> System >> Advanced System Settings.

Select the "UserVars.ESXiShellInteractiveTimeOut" value and verify it is set to "900" or less and not "0".

or

From a PowerCLI command prompt while connected to the ESXi host, run the following command:

Get-VMHost | Get-AdvancedSetting -Name UserVars.ESXiShellInteractiveTimeOut

If the "UserVars.ESXiShellInteractiveTimeOut" setting is set to a value greater than "900" or "0", this is a finding.'
  desc 'fix', 'From the vSphere Client, go to Hosts and Clusters.

Select the ESXi Host >> Configure >> System >> Advanced System Settings.

Click "Edit". Select the "UserVars.ESXiShellInteractiveTimeOut" value and configure it to "900".

or

From a PowerCLI command prompt while connected to the ESXi host, run the following command:

Get-VMHost | Get-AdvancedSetting -Name UserVars.ESXiShellInteractiveTimeOut | Set-AdvancedSetting -Value 900'
  impact 0.5
  tag check_id: 'C-62479r1003518_chk'
  tag severity: 'medium'
  tag gid: 'V-258739'
  tag rid: 'SV-258739r1003562_rule'
  tag stig_id: 'ESXI-80-000068'
  tag gtitle: 'SRG-OS-000163-VMM-000700'
  tag fix_id: 'F-62388r933277_fix'
  tag satisfies: ['SRG-OS-000163-VMM-000700', 'SRG-OS-000279-VMM-001010']
  tag cci: ['CCI-001133', 'CCI-002361']
  tag nist: ['SC-10', 'AC-12']

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
        its('stdout.strip') { should cmp <= 900 }
        its('stdout.strip') { should_not cmp 0 }
      end
    end
  else
    describe 'No hosts found!' do
      skip 'No hosts found...skipping tests'
    end
  end
end
