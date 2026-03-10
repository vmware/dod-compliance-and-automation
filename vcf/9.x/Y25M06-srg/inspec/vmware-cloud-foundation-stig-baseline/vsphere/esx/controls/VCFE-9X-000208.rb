control 'VCFE-9X-000208' do
  title 'The ESX host Secure Shell (SSH) daemon must not permit user environment settings.'
  desc  'SSH environment options potentially allow users to bypass access restriction in some configurations. Users must not be able to present environment options to the SSH daemon.'
  desc  'rationale', ''
  desc  'check', "
    From an ESX shell, run the following command:

    # esxcli system ssh server config list -k permituserenvironment

    or

    From a PowerCLI command prompt while connected to the ESX host, run the following commands:

    $esxcli = Get-EsxCli -v2
    $esxcli.system.ssh.server.config.list.invoke() | Where-Object {$_.Key -eq 'permituserenvironment'}

    Example result:

    permituserenvironment no

    If \"permituserenvironment\" is not configured to \"no\", this is a finding.
  "
  desc 'fix', "
    From an ESX shell, run the following command:

    # esxcli system ssh server config set -k permituserenvironment -v no

    or

    From a PowerCLI command prompt while connected to the ESX host, run the following commands:

    $esxcli = Get-EsxCli -v2
    $arguments = $esxcli.system.ssh.server.config.set.CreateArgs()
    $arguments.keyword = 'permituserenvironment'
    $arguments.value = 'no'
    $esxcli.system.ssh.server.config.set.Invoke($arguments)
  "
  impact 0.5
  tag severity: 'medium'
  tag gtitle: 'SRG-OS-000480-VMM-002000'
  tag gid: 'V-VCFE-9X-000208'
  tag rid: 'SV-VCFE-9X-000208'
  tag stig_id: 'VCFE-9X-000208'
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
      command = "$vmhost = Get-VMHost -Name #{vmhost}; $esxcli = Get-EsxCli -VMHost $vmhost -V2; $esxcli.system.ssh.server.config.list.invoke() | Where-Object {$_.Key -eq 'permituserenvironment'} | Select-Object -ExpandProperty Value"
      describe powercli_command(command) do
        its('stdout.strip') { should cmp 'no' }
      end
    end
  end
end
