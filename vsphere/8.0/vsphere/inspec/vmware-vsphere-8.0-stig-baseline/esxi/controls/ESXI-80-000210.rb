control 'ESXI-80-000210' do
  title 'The ESXi host Secure Shell (SSH) daemon must set a timeout count on idle sessions.'
  desc 'Setting a timeout ensures that a user login will be terminated as soon as the "ClientAliveCountMax" is reached.'
  desc 'check', %q(From an ESXi shell, run the following command:

# esxcli system ssh server config list -k clientalivecountmax

or

From a PowerCLI command prompt while connected to the ESXi host, run the following commands:

$esxcli = Get-EsxCli -v2
$esxcli.system.ssh.server.config.list.invoke() | Where-Object {$_.Key -eq 'clientalivecountmax'}

Example result:

clientalivecountmax 3

If "clientalivecountmax" is not configured to "3", this is a finding.)
  desc 'fix', "From an ESXi shell, run the following command:

# esxcli system ssh server config set -k clientalivecountmax -v 3

or

From a PowerCLI command prompt while connected to the ESXi host, run the following commands:

$esxcli = Get-EsxCli -v2
$arguments = $esxcli.system.ssh.server.config.set.CreateArgs()
$arguments.keyword = 'clientalivecountmax'
$arguments.value = '3'
$esxcli.system.ssh.server.config.set.Invoke($arguments)"
  impact 0.3
  tag check_id: 'C-62505r933354_chk'
  tag severity: 'low'
  tag gid: 'V-258765'
  tag rid: 'SV-258765r933356_rule'
  tag stig_id: 'ESXI-80-000210'
  tag gtitle: 'SRG-OS-000480-VMM-002000'
  tag fix_id: 'F-62414r933355_fix'
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
      command = "$vmhost = Get-VMHost -Name #{vmhost}; $esxcli = Get-EsxCli -VMHost $vmhost -V2; $esxcli.system.ssh.server.config.list.invoke() | Where-Object {$_.Key -eq 'clientalivecountmax'} | Select-Object -ExpandProperty Value"
      describe powercli_command(command) do
        its('stdout.strip') { should cmp '3' }
      end
    end
  else
    describe 'No hosts found!' do
      skip 'No hosts found...skipping tests'
    end
  end
end
