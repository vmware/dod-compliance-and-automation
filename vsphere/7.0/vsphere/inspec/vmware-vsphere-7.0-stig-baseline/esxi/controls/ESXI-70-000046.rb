control 'ESXI-70-000046' do
  title 'The ESXi host must configure NTP time synchronization.'
  desc 'To ensure the accuracy of the system clock, it must be synchronized with an authoritative time source within DOD. Many system functions, including time-based logon and activity restrictions, automated reports, system logs, and audit records, depend on an accurate system clock. If there is no confidence in the correctness of the system clock, time-based functions may not operate as intended and records may be of diminished value.

'
  desc 'check', 'From the vSphere Client, go to Hosts and Clusters.

Select the ESXi Host >> Configure >> System >> Time Configuration.

Under "Current Time Configuration", verify "Time Synchronization" is set to "Network Time Protocol".

Under "Network Time Protocol", verify the "NTP Servers" are authorized DOD time sources.

If the ESXi host is not configured to pull time from authoritative DOD time sources, this is a finding.

or

From a PowerCLI command prompt while connected to the ESXi host, run the following commands:

Get-VMHost | Get-VMHostNTPServer
Get-VMHost | Get-VMHostService | Where {$_.Label -eq "NTP Daemon"}

If the NTP service is not configured with authoritative DOD time sources or the service does not have a "Policy" of "on" or is stopped, this is a finding.'
  desc 'fix', 'From the vSphere Client, go to Hosts and Clusters.

Select the ESXi Host >> Configure >> System >> Time Configuration.

Under "Network Time Protocol", click "Edit...". Ensure the "NTP Servers" are authorized DOD time sources.

Ensure the "NTP Service Startup Policy" is set to "Start and stop with host".

Ensure the "Enable" checkbox, in the upper left, is checked. Click "OK".

Click "Edit" to configure the NTP service to start and stop with the host and with authoritative DOD time sources.

or

From a PowerCLI command prompt while connected to the ESXi host, run the following commands:

$NTPServers = "ntpserver1","ntpserver2"
Get-VMHost | Add-VMHostNTPServer $NTPServers
Get-VMHost | Get-VMHostService | Where {$_.Label -eq "NTP Daemon"} | Set-VMHostService -Policy On
Get-VMHost | Get-VMHostService | Where {$_.Label -eq "NTP Daemon"} | Start-VMHostService'
  impact 0.5
  tag check_id: 'C-60084r886006_chk'
  tag severity: 'medium'
  tag gid: 'V-256409'
  tag rid: 'SV-256409r886008_rule'
  tag stig_id: 'ESXI-70-000046'
  tag gtitle: 'SRG-OS-000355-VMM-001330'
  tag fix_id: 'F-60027r886007_fix'
  tag satisfies: ['SRG-OS-000355-VMM-001330', 'SRG-OS-000356-VMM-001340']
  tag cci: ['CCI-001891', 'CCI-002046']
  tag nist: ['AU-8 (1) (a)', 'AU-8 (1) (b)']

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
      command = "Get-VMHost -Name #{vmhost} | Get-VMHostService | Where {$_.Label -eq 'NTP Daemon'} | Select-Object -ExpandProperty Policy"
      describe powercli_command(command) do
        its('stdout.strip') { should cmp 'on' }
      end
      command = "Get-VMHost -Name #{vmhost} | Get-VMHostService | Where {$_.Label -eq 'NTP Daemon'} | Select-Object -ExpandProperty Running"
      describe powercli_command(command) do
        its('stdout.strip') { should cmp 'true' }
      end
      results = powercli_command("Get-VMHost -Name #{vmhost} | Get-VMHostNTPServer").stdout
      if !results.empty?
        results.gsub("\r\n", "\n").split("\n").each do |result|
          describe "NTP Server: #{result} for VMHost: #{vmhost}" do
            subject { result }
            it { should be_in "#{input('esxiNtpServers')}" }
          end
        end
      else
        describe "No NTP servers found on VMhost: #{vmhost}" do
          subject { results }
          it { should_not be_empty }
        end
      end
    end
  else
    describe 'No hosts found!' do
      skip 'No hosts found...skipping tests'
    end
  end
end
