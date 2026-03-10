control 'ESXI-80-000235' do
  title 'The ESXi host must forward audit records containing information to establish what type of events occurred.'
  desc 'Without establishing what types of events occurred, it would be difficult to establish, correlate, and investigate the events leading up to an outage or attack.

Audit record content that may be necessary to satisfy this requirement includes, for example, time stamps, source and destination addresses, user/process/VM identifiers, event descriptions, success/fail indications, filenames involved, and access control or flow control rules invoked.

Associating event types with detected events in the ESXi audit logs provides a means of investigating an attack; recognizing resource utilization or capacity thresholds; or identifying an improperly configured host.'
  desc 'check', 'From the vSphere Client, go to Hosts and Clusters.

Select the ESXi Host >> Configure >> System >> Advanced System Settings.

Select the "Syslog.global.logLevel" value and verify it is set to "info".

or

From a PowerCLI command prompt while connected to the ESXi host, run the following command:

Get-VMHost | Get-AdvancedSetting -Name Syslog.global.logLevel

If the "Syslog.global.logLevel" setting is not set to "info", this is a finding.

Note: Verbose logging level is acceptable for troubleshooting purposes.'
  desc 'fix', 'From the vSphere Client, go to Hosts and Clusters.

Select the ESXi Host >> Configure >> System >> Advanced System Settings.

Click "Edit". Select the "Syslog.global.logLevel" value and configure it to "info".

or

From a PowerCLI command prompt while connected to the ESXi host, run the following command:

Get-VMHost | Get-AdvancedSetting -Name Syslog.global.logLevel | Set-AdvancedSetting -Value "info"'
  impact 0.5
  tag check_id: 'C-62530r933429_chk'
  tag severity: 'medium'
  tag gid: 'V-258790'
  tag rid: 'SV-258790r958412_rule'
  tag stig_id: 'ESXI-80-000235'
  tag gtitle: 'SRG-OS-000037-VMM-000150'
  tag fix_id: 'F-62439r933430_fix'
  tag cci: ['CCI-000130']
  tag nist: ['AU-3 a']

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
      command = "Get-VMHost -Name #{vmhost} | Get-AdvancedSetting -Name Syslog.global.logLevel | Select-Object -ExpandProperty Value"
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
