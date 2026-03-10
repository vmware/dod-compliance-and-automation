control 'ESXI-70-000030' do
  title 'The ESXi host must produce audit records containing information to establish what type of events occurred.'
  desc 'Without establishing what types of events occurred, it would be difficult to establish, correlate, and investigate the events leading up to an outage or attack.

'
  desc 'check', 'From the vSphere Client, go to Hosts and Clusters.

Select the ESXi Host >> Configure >> System >> Advanced System Settings.

Select the "Config.HostAgent.log.level" value and verify it is set to "info".

or

From a PowerCLI command prompt while connected to the ESXi host, run the following command:

Get-VMHost | Get-AdvancedSetting -Name Config.HostAgent.log.level

If the "Config.HostAgent.log.level" setting is not set to "info", this is a finding.

Note: Verbose logging level is acceptable for troubleshooting purposes.'
  desc 'fix', 'From the vSphere Client, go to Hosts and Clusters.

Select the ESXi Host >> Configure >> System >> Advanced System Settings. Click "Edit".

Select the "Config.HostAgent.log.level" value and configure it to "info".

or

From a PowerCLI command prompt while connected to the ESXi host, run the following command:

Get-VMHost | Get-AdvancedSetting -Name Config.HostAgent.log.level | Set-AdvancedSetting -Value "info"'
  impact 0.5
  tag check_id: 'C-60071r885967_chk'
  tag severity: 'medium'
  tag gid: 'V-256396'
  tag rid: 'SV-256396r885969_rule'
  tag stig_id: 'ESXI-70-000030'
  tag gtitle: 'SRG-OS-000037-VMM-000150'
  tag fix_id: 'F-60014r885968_fix'
  tag satisfies: ['SRG-OS-000037-VMM-000150', 'SRG-OS-000063-VMM-000310']
  tag cci: ['CCI-000130', 'CCI-000171']
  tag nist: ['AU-3 a', 'AU-12 b']

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
      command = "Get-VMHost -Name #{vmhost} | Get-AdvancedSetting -Name Config.HostAgent.log.level | Select-Object -ExpandProperty Value"
      describe powercli_command(command) do
        its('stdout.strip') { should cmp 'info' }
      end
    end
  else
    describe 'No hosts found!' do
      skip 'No hosts found...skipping tests'
    end
  end
end
