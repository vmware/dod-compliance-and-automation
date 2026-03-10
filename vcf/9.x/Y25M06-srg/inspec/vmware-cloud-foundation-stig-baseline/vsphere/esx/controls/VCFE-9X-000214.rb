control 'VCFE-9X-000214' do
  title 'The ESX host Secure Shell (SSH) daemon must not allow host-based authentication.'
  desc  "SSH trust relationships mean a compromise on one host can allow an attacker to move trivially to other hosts. SSH's cryptographic host-based authentication is more secure than \".rhosts\" authentication since hosts are cryptographically authenticated. However, it is not recommended that hosts unilaterally trust one another, even within an organization."
  desc  'rationale', ''
  desc  'check', "
    From an ESX shell, run the following command:

    # esxcli system ssh server config list -k hostbasedauthentication

    or

    From a PowerCLI command prompt while connected to the ESX host, run the following commands:

    $esxcli = Get-EsxCli -v2
    $esxcli.system.ssh.server.config.list.invoke() | Where-Object {$_.Key -eq 'hostbasedauthentication'}

    Example result:

    hostbasedauthentication no

    If \"hostbasedauthentication\" is not configured to \"no\", this is a finding.
  "
  desc 'fix', "
    From an ESX shell, run the following command:

    # esxcli system ssh server config set -k hostbasedauthentication -v no

    or

    From a PowerCLI command prompt while connected to the ESX host, run the following commands:

    $esxcli = Get-EsxCli -v2
    $arguments = $esxcli.system.ssh.server.config.set.CreateArgs()
    $arguments.keyword = 'hostbasedauthentication'
    $arguments.value = 'no'
    $esxcli.system.ssh.server.config.set.Invoke($arguments)
  "
  impact 0.5
  tag severity: 'medium'
  tag gtitle: 'SRG-OS-000480-VMM-002000'
  tag gid: 'V-VCFE-9X-000214'
  tag rid: 'SV-VCFE-9X-000214'
  tag stig_id: 'VCFE-9X-000214'
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
      command = "$vmhost = Get-VMHost -Name #{vmhost}; $esxcli = Get-EsxCli -VMHost $vmhost -V2; $esxcli.system.ssh.server.config.list.invoke() | Where-Object {$_.Key -eq 'hostbasedauthentication'} | Select-Object -ExpandProperty Value"
      describe powercli_command(command) do
        its('stdout.strip') { should cmp 'no' }
      end
    end
  end
end
