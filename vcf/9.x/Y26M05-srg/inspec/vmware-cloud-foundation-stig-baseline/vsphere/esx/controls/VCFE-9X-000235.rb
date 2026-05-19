control 'VCFE-9X-000235' do
  title 'The ESX host must not enable log filtering.'
  desc  "
    The log filtering capability allows users to modify the logging policy of the syslog service that is running on an ESX host. Users can create log filters to reduce the number of repetitive entries in the ESX logs and to deny specific log events entirely.

    Setting a limit to the amount of logging information restricts the ability to detect and respond to potential security issues or system failures properly.
  "
  desc  'rationale', ''
  desc  'check', "
    From an ESX shell, run the following command:

    # esxcli system syslog config logfilter get

    or

    From a PowerCLI command prompt while connected to the ESX host, run the following commands:

    $esxcli = Get-EsxCli -v2
    $esxcli.system.syslog.config.logfilter.get.invoke()

    If \"LogFilteringEnabled\" is not set to \"false\", this is a finding.
  "
  desc 'fix', "
    From an ESX shell, run the following command:

    # esxcli system syslog config logfilter set --log-filtering-enabled=false

    or

    From a PowerCLI command prompt while connected to the ESX host, run the following commands:

    $esxcli = Get-EsxCli -v2
    $arguments = $esxcli.system.syslog.config.logfilter.set.CreateArgs()
    $arguments.logfilteringenabled = $false
    $esxcli.system.syslog.config.logfilter.set.invoke($arguments)
  "
  impact 0.5
  tag severity: 'medium'
  tag gtitle: 'SRG-OS-000480-VMM-002000'
  tag gid: 'V-VCFE-9X-000235'
  tag rid: 'SV-VCFE-9X-000235'
  tag stig_id: 'VCFE-9X-000235'
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']

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
      command = "$vmhost = Get-VMHost -Name #{vmhost}; $esxcli = Get-EsxCli -VMHost $vmhost -V2; $esxcli.system.syslog.config.logfilter.get.invoke() | Select-Object -ExpandProperty LogFilteringEnabled"
      describe powercli_command(command) do
        its('stdout.strip') { should cmp 'false' }
      end
    end
  end
end
