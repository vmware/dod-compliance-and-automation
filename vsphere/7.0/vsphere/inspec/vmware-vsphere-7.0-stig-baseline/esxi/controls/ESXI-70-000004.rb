control 'ESXI-70-000004' do
  title 'Remote logging for ESXi hosts must be configured.'
  desc 'Remote logging to a central log host provides a secure, centralized store for ESXi logs. By gathering host log files onto a central host, it can more easily monitor all hosts with a single tool. It can also do aggregate analysis and searching to look for such things as coordinated attacks on multiple hosts.

Logging to a secure, centralized log server also helps prevent log tampering and provides a long-term audit record.

'
  desc 'check', 'From the vSphere Client, go to Hosts and Clusters.

Select the ESXi Host >> Configure >> System >> Advanced System Settings.

Select the "Syslog.global.logHost" value and verify it is set to a site-specific syslog server.

Follow the conventions shown below:

udp://<IP/FQDN>:514
tcp://<IP/FQDN>:514
ssl://<IP/FQDN>:1514

Multiple servers can be specified when separated by commas.

or

From a PowerCLI command prompt while connected to the ESXi host, run the following command:

Get-VMHost | Get-AdvancedSetting -Name Syslog.global.logHost

If the "Syslog.global.logHost" setting is not set to a valid, site-specific syslog server, this is a finding.'
  desc 'fix', 'From the vSphere Client, go to Hosts and Clusters.

Select the ESXi Host >> Configure >> System >> Advanced System Settings.

Click "Edit". Select the "Syslog.global.logHost" value and configure it to a site-specific syslog server.

or

From a PowerCLI command prompt while connected to the ESXi host, run the following command:

Get-VMHost | Get-AdvancedSetting -Name Syslog.global.logHost | Set-AdvancedSetting -Value "<syslog server hostname>"'
  impact 0.5
  tag check_id: 'C-60053r885913_chk'
  tag severity: 'medium'
  tag gid: 'V-256378'
  tag rid: 'SV-256378r885915_rule'
  tag stig_id: 'ESXI-70-000004'
  tag gtitle: 'SRG-OS-000032-VMM-000130'
  tag fix_id: 'F-59996r885914_fix'
  tag satisfies: ['SRG-OS-000032-VMM-000130', 'SRG-OS-000342-VMM-001230', 'SRG-OS-000479-VMM-001990', 'SRG-OS-000059-VMM-000280', 'SRG-OS-000058-VMM-000270', 'SRG-OS-000051-VMM-000230']
  tag cci: ['CCI-000067', 'CCI-000154', 'CCI-000163', 'CCI-000164', 'CCI-001851']
  tag nist: ['AC-17 (1)', 'AU-6 (4)', 'AU-9 a', 'AU-9 a', 'AU-4 (1)']

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
