control 'ESXI-80-000052' do
  title 'The ESXi host Secure Shell (SSH) daemon must ignore .rhosts files.'
  desc  'SSH trust relationships mean a compromise on one host can allow an attacker to move trivially to other hosts. SSH can emulate the behavior of the obsolete "rsh" command in allowing users to enable insecure access to their accounts via ".rhosts" files.'
  desc  'rationale', ''
  desc  'check', "
    From an ESXi shell, run the following command:

    # esxcli system ssh server config list -k ignorerhosts

    or

    From a PowerCLI command prompt while connected to the ESXi host, run the following commands:

    $esxcli = Get-EsxCli -v2
    $esxcli.system.ssh.server.config.list.invoke() | Where-Object {$_.Key -eq 'ignorerhosts'}

    Example result:

    ignorerhosts yes

    If \"ignorerhosts\" is not configured to \"yes\", this is a finding.
  "
  desc 'fix', "
    From an ESXi shell, run the following command:

    # esxcli system ssh server config set -k ignorerhosts -v yes

    or

    From a PowerCLI command prompt while connected to the ESXi host, run the following commands:

    $esxcli = Get-EsxCli -v2
    $arguments = $esxcli.system.ssh.server.config.set.CreateArgs()
    $arguments.keyword = 'ignorerhosts'
    $arguments.value = 'yes'
    $esxcli.system.ssh.server.config.set.Invoke($arguments)
  "
  impact 0.5
  tag severity: 'medium'
  tag gtitle: 'SRG-OS-000107-VMM-000530'
  tag gid: 'V-ESXI-80-000052'
  tag rid: 'SV-ESXI-80-000052'
  tag stig_id: 'ESXI-80-000052'
  tag cci: ['CCI-000767']
  tag nist: ['IA-2 (3)']

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
      command = "$vmhost = Get-VMHost -Name #{vmhost}; $esxcli = Get-EsxCli -VMHost $vmhost -V2; $esxcli.system.ssh.server.config.list.invoke() | Where-Object {$_.Key -eq 'ignorerhosts'} | Select-Object -ExpandProperty Value"
      describe powercli_command(command) do
        its('stdout.strip') { should cmp 'yes' }
      end
    end
  else
    describe 'No hosts found!' do
      skip 'No hosts found...skipping tests'
    end
  end
end
