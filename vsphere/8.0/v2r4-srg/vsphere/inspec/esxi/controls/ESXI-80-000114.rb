control 'ESXI-80-000114' do
  title 'The ESXi host must offload logs via syslog.'
  desc 'Remote logging to a central log host provides a secure, centralized store for ESXi logs. By gathering host log files onto a central host, it can more easily monitor all hosts with a single tool. It can also do aggregate analysis and searching to look for such things as coordinated attacks on multiple hosts.

Logging to a secure, centralized log server also helps prevent log tampering and provides a long-term audit record.
'
  desc 'check', 'From the vSphere Client, go to Hosts and Clusters.

Select the ESXi Host >> Configure >> System >> Advanced System Settings.

Select the "Syslog.global.logHost" value and verify it is set to a site-specific syslog server.

Syslog servers are specified in the following formats:

udp://<IP or FQDN>:514
tcp://<IP or FQDN>:514
ssl://<IP or FQDN>:1514

Multiple servers can also be specified when separated by commas.

or

From a PowerCLI command prompt while connected to the ESXi host, run the following command:

Get-VMHost | Get-AdvancedSetting -Name Syslog.global.logHost

If the "Syslog.global.logHost" setting is not set to a valid, site-specific syslog server, this is a finding.'
  desc 'fix', 'From the vSphere Client, go to Hosts and Clusters.

Select the ESXi Host >> Configure >> System >> Advanced System Settings.

Click "Edit". Select the "Syslog.global.logHost" value and configure it to a site-specific syslog server.

or

From a PowerCLI command prompt while connected to the ESXi host, run the following command:

Get-VMHost | Get-AdvancedSetting -Name Syslog.global.logHost | Set-AdvancedSetting -Value "enter site specific servers"'
  impact 0.5
  tag check_id: 'C-62484r933291_chk'
  tag severity: 'medium'
  tag gid: 'V-258744'
  tag rid: 'SV-258744r1003565_rule'
  tag stig_id: 'ESXI-80-000114'
  tag gtitle: 'SRG-OS-000342-VMM-001230'
  tag fix_id: 'F-62393r933292_fix'
  tag satisfies: ['SRG-OS-000342-VMM-001230', 'SRG-OS-000274-VMM-000960', 'SRG-OS-000275-VMM-000970', 'SRG-OS-000277-VMM-000990', 'SRG-OS-000479-VMM-001990']
  tag cci: ['CCI-000015', 'CCI-001851']
  tag nist: ['AC-2 (1)', 'AU-4 (1)']

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
      command = "Get-VMHost -Name #{vmhost} | Get-AdvancedSetting -Name Syslog.global.logHost | Select-Object -ExpandProperty Value"
      describe powercli_command(command) do
        its('stdout.strip') { should cmp "#{input('syslogServer')}" }
      end
    end
  else
    describe 'No hosts found!' do
      skip 'No hosts found...skipping tests'
    end
  end
end
