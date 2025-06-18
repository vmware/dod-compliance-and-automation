control 'VCFE-9X-000121' do
  title 'The ESX host must synchronize internal information system clocks to an authoritative time source.'
  desc  'To ensure the accuracy of the system clock, it must be synchronized with an authoritative time source within DOD. Many system functions, including time-based logon and activity restrictions, automated reports, system logs, and audit records, depend on an accurate system clock. If there is no confidence in the correctness of the system clock, time-based functions may not operate as intended and records may be of diminished value.'
  desc  'rationale', ''
  desc  'check', "
    From the vSphere Client, go to Hosts and Clusters.

    Select the ESX Host >> Configure >> System >> Time Configuration.

    Verify NTP or PTP are configured, and one or more authoritative time sources are listed.

    From the vSphere Client, go to Hosts and Clusters.

    Select the ESX Host >> Configure >> System >> Services.

    Verify the NTP or PTP service is running and configured to start and stop with the host.

    or

    From a PowerCLI command prompt while connected to the ESX host, run the following commands:

    Get-VMHost | Get-VMHostNTPServer
    Get-VMHost | Get-VMHostService | Where {$_.Label -eq \"NTP Daemon\" -or $_.Label -eq \"PTP Daemon\"}

    If the NTP service is not configured with authoritative DOD time sources or the service is not configured to start and stop with the host (\"Policy\" of \"on\" in PowerCLI) or is stopped, this is a finding.

    If PTP is used instead of NTP, this is not a finding.
  "
  desc 'fix', "
    To configure NTP, perform the following:

    From the vSphere Client, go to Hosts and Clusters.

    Select the ESX Host >> Configure >> System >> Time Configuration.

    Click \"Add Service\" and select \"Network Time Protocol\".

    Enter or update the NTP servers listed with a comma-separated list of authoritative time servers. Click \"OK\".

    From the vSphere Client, go to Hosts and Clusters.

    Select the ESX Host >> Configure >> System >> Services.

    Select the \"NTP Daemon\" service and click \"Edit Startup Policy\".

    Select \"Start and stop with host\". Click \"OK\".

    or

    From a PowerCLI command prompt while connected to the ESX host, run the following commands:

    $NTPServers = \"ntpserver1\",\"ntpserver2\"
    Get-VMHost | Add-VMHostNTPServer $NTPServers
    Get-VMHost | Get-VMHostService | Where {$_.Label -eq \"NTP Daemon\"} | Set-VMHostService -Policy On
    Get-VMHost | Get-VMHostService | Where {$_.Label -eq \"NTP Daemon\"} | Start-VMHostService

    To configure PTP, perform the following:

    From the vSphere Client, go to Hosts and Clusters.

    Select the ESX Host >> Configure >> System >> Time Configuration.

    Click \"Add Service\" and select \"Precision Time Protocol\".

    Select the network adapter that can receive the PTP traffic.

    If NTP servers are available, select \"Enable fallback\" and enter or update the NTP servers listed with a comma separated list of authoritative time servers. Click \"OK\".

    From the vSphere Client, go to Hosts and Clusters.

    Select the ESX Host >> Configure >> System >> Services.

    Select the \"PTP Daemon\" service and click \"Edit Startup Policy\".

    Select \"Start and stop with host\". Click \"OK\".
  "
  impact 0.5
  tag severity: 'medium'
  tag gtitle: 'SRG-OS-000355-VMM-001330'
  tag satisfies: ['SRG-OS-000356-VMM-001340', 'SRG-OS-000785-VMM-000250']
  tag gid: 'V-VCFE-9X-000121'
  tag rid: 'SV-VCFE-9X-000121'
  tag stig_id: 'VCFE-9X-000121'
  tag cci: ['CCI-004922', 'CCI-004923', 'CCI-004926']
  tag nist: ['SC-45', 'SC-45 (1) (a)', 'SC-45 (1) (b)']

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
      command = "Get-VMHost -Name #{vmhost} | Get-VMHostService | Where {$_.Label -eq 'NTP Daemon'} | Select-Object -ExpandProperty Policy"
      describe powercli_command(command) do
        its('stdout.strip') { should cmp 'on' }
      end
      command = "Get-VMHost -Name #{vmhost} | Get-VMHostService | Where {$_.Label -eq 'NTP Daemon'} | Select-Object -ExpandProperty Running"
      describe powercli_command(command) do
        its('stdout.strip') { should cmp 'true' }
      end
      results = powercli_command("Get-VMHost -Name #{vmhost} | Get-VMHostNTPServer").stdout
      if !results.blank?
        results.gsub("\r\n", "\n").split("\n").each do |result|
          describe "NTP Server: #{result} for VMHost: #{vmhost}" do
            subject { result }
            it { should be_in "#{input('esx_ntpServers')}" }
          end
        end
      else
        describe "No NTP servers found on VMhost: #{vmhost}" do
          subject { results }
          it { should_not be_blank }
        end
      end
    end
  end
end
