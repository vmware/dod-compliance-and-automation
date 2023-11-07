control 'ESXI-80-000207' do
  title 'The ESXi host Secure Shell (SSH) daemon must be configured to not allow gateway ports.'
  desc 'SSH Transmission Control Protocol (TCP) connection forwarding provides a mechanism to establish TCP connections proxied by the SSH server. This function can provide convenience similar to a virtual private network (VPN) with the similar risk of providing a path to circumvent firewalls and network Access Control Lists (ACLs). Gateway ports allow remote forwarded ports to bind to nonloopback addresses on the server.'
  desc 'check', %q(From an ESXi shell, run the following command:

# esxcli system ssh server config list -k gatewayports

or

From a PowerCLI command prompt while connected to the ESXi host, run the following commands:

$esxcli = Get-EsxCli -v2
$esxcli.system.ssh.server.config.list.invoke() | Where-Object {$_.Key -eq 'gatewayports'}

Example result:

gatewayports no

If "gatewayports" is not configured to "no", this is a finding.)
  desc 'fix', "From an ESXi shell, run the following command:

# esxcli system ssh server config set -k gatewayports -v no

or

From a PowerCLI command prompt while connected to the ESXi host, run the following commands:

$esxcli = Get-EsxCli -v2
$arguments = $esxcli.system.ssh.server.config.set.CreateArgs()
$arguments.keyword = 'gatewayports'
$arguments.value = 'no'
$esxcli.system.ssh.server.config.set.Invoke($arguments)"
  impact 0.3
  tag check_id: 'C-62503r933348_chk'
  tag severity: 'low'
  tag gid: 'V-258763'
  tag rid: 'SV-258763r933350_rule'
  tag stig_id: 'ESXI-80-000207'
  tag gtitle: 'SRG-OS-000480-VMM-002000'
  tag fix_id: 'F-62412r933349_fix'
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
      command = "$vmhost = Get-VMHost -Name #{vmhost}; $esxcli = Get-EsxCli -VMHost $vmhost -V2; $esxcli.system.ssh.server.config.list.invoke() | Where-Object {$_.Key -eq 'gatewayports'} | Select-Object -ExpandProperty Value"
      describe powercli_command(command) do
        its('stdout.strip') { should cmp 'no' }
      end
    end
  else
    describe 'No hosts found!' do
      skip 'No hosts found...skipping tests'
    end
  end
end
