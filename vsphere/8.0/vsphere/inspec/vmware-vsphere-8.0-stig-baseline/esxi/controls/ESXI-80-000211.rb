control 'ESXI-80-000211' do
  title 'The ESXi host Secure Shell (SSH) daemon must set a timeout interval on idle sessions.'
  desc 'Automatically logging out idle users guards against compromises via hijacked administrative sessions.'
  desc 'check', %q(From an ESXi shell, run the following command:

# esxcli system ssh server config list -k clientaliveinterval

or

From a PowerCLI command prompt while connected to the ESXi host, run the following commands:

$esxcli = Get-EsxCli -v2
$esxcli.system.ssh.server.config.list.invoke() | Where-Object {$_.Key -eq 'clientaliveinterval'}

Example result:

clientaliveinterval 200

If "clientaliveinterval" is not configured to "200", this is a finding.)
  desc 'fix', "From an ESXi shell, run the following command:

# esxcli system ssh server config set -k clientaliveinterval -v 200

or

From a PowerCLI command prompt while connected to the ESXi host, run the following commands:

$esxcli = Get-EsxCli -v2
$arguments = $esxcli.system.ssh.server.config.set.CreateArgs()
$arguments.keyword = 'clientaliveinterval'
$arguments.value = '200'
$esxcli.system.ssh.server.config.set.Invoke($arguments)"
  impact 0.3
  tag check_id: 'C-62506r933357_chk'
  tag severity: 'low'
  tag gid: 'V-258766'
  tag rid: 'SV-258766r933359_rule'
  tag stig_id: 'ESXI-80-000211'
  tag gtitle: 'SRG-OS-000480-VMM-002000'
  tag fix_id: 'F-62415r933358_fix'
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
      command = "$vmhost = Get-VMHost -Name #{vmhost}; $esxcli = Get-EsxCli -VMHost $vmhost -V2; $esxcli.system.ssh.server.config.list.invoke() | Where-Object {$_.Key -eq 'clientaliveinterval'} | Select-Object -ExpandProperty Value"
      describe powercli_command(command) do
        its('stdout.strip') { should cmp '200' }
      end
    end
  else
    describe 'No hosts found!' do
      skip 'No hosts found...skipping tests'
    end
  end
end
