control 'ESXI-80-000214' do
  title 'The ESXi host must configure the firewall to block network traffic by default.'
  desc 'In addition to service-specific firewall rules, ESXi has a default firewall rule policy to allow or deny incoming and outgoing traffic. Reduce the risk of attack by ensuring this is set to deny incoming and outgoing traffic.'
  desc 'check', 'From an ESXi shell, run the following command:

# esxcli network firewall get

or

From a PowerCLI command prompt while connected to the ESXi host, run the following commands:

$esxcli = Get-EsxCli -v2
$esxcli.network.firewall.get.invoke()

If the "Default Action" does not equal "DROP", this is a finding.
If "Enabled" does not equal "true", this is a finding.'
  desc 'fix', 'From an ESXi shell, run the following command:

# esxcli network firewall set --default-action false --enabled true

or

From a PowerCLI command prompt while connected to the ESXi host, run the following commands:

$esxcli = Get-EsxCli -v2
$arguments = $esxcli.network.firewall.set.CreateArgs()
$arguments.enabled = $true
$arguments.defaultaction = $false
$esxcli.network.firewall.set.Invoke($arguments)'
  impact 0.5
  tag check_id: 'C-62509r1003533_chk'
  tag severity: 'medium'
  tag gid: 'V-258769'
  tag rid: 'SV-258769r1003571_rule'
  tag stig_id: 'ESXI-80-000214'
  tag gtitle: 'SRG-OS-000480-VMM-002000'
  tag fix_id: 'F-62418r1003534_fix'
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
      command1 = "$vmhost = Get-VMHost -Name #{vmhost}; $esxcli = Get-EsxCli -VMHost $vmhost -V2; $esxcli.network.firewall.get.invoke() | Select-Object -ExpandProperty Enabled"
      describe powercli_command(command1) do
        its('stdout.strip') { should cmp 'true' }
      end
      command2 = "$vmhost = Get-VMHost -Name #{vmhost}; $esxcli = Get-EsxCli -VMHost $vmhost -V2; $esxcli.network.firewall.get.invoke() | Select-Object -ExpandProperty DefaultAction"
      describe powercli_command(command2) do
        its('stdout.strip') { should cmp 'DROP' }
      end
    end
  else
    describe 'No hosts found!' do
      skip 'No hosts found...skipping tests'
    end
  end
end
