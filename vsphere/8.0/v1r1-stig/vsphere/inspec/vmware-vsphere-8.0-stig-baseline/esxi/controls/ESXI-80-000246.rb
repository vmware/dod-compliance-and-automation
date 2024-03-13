control 'ESXI-80-000246' do
  title 'The ESXi host must not enable log filtering.'
  desc 'The log filtering capability allows users to modify the logging policy of the syslog service that is running on an ESXi host. Users can create log filters to reduce the number of repetitive entries in the ESXi logs and to deny specific log events entirely.

Setting a limit to the amount of logging information restricts the ability to detect and respond to potential security issues or system failures properly.'
  desc 'check', 'From an ESXi shell, run the following command:

# esxcli system syslog config logfilter get

or

From a PowerCLI command prompt while connected to the ESXi host, run the following commands:

$esxcli = Get-EsxCli -v2
$esxcli.system.syslog.config.logfilter.get.invoke()

If "LogFilteringEnabled" is not set to "false", this is a finding.'
  desc 'fix', 'From an ESXi shell, run the following command:

# esxcli system syslog config logfilter set --log-filtering-enabled=false

or

From a PowerCLI command prompt while connected to the ESXi host, run the following commands:

$esxcli = Get-EsxCli -v2
$arguments = $esxcli.system.syslog.config.logfilter.set.CreateArgs()
$arguments.logfilteringenabled = $false
$esxcli.system.syslog.config.logfilter.set.invoke($arguments)'
  impact 0.5
  tag check_id: 'C-62540r933459_chk'
  tag severity: 'medium'
  tag gid: 'V-258800'
  tag rid: 'SV-258800r933461_rule'
  tag stig_id: 'ESXI-80-000246'
  tag gtitle: 'SRG-OS-000480-VMM-002000'
  tag fix_id: 'F-62449r933460_fix'
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']

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
      command = "$vmhost = Get-VMHost -Name #{vmhost}; $esxcli = Get-EsxCli -VMHost $vmhost -V2; $esxcli.system.syslog.config.logfilter.get.invoke() | Select-Object -ExpandProperty LogFilteringEnabled"
      describe powercli_command(command) do
        its('stdout.strip') { should cmp 'false' }
      end
    end
  else
    describe 'No hosts found!' do
      skip 'No hosts found...skipping tests'
    end
  end
end
