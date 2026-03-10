control 'VCFE-9X-000237' do
  title 'The ESX host must deny shell access for the dcui account.'
  desc  'The dcui user is used for process isolation for the DCUI itself. The account has shell access which can be deactivated to reduce attack surface.'
  desc  'rationale', ''
  desc  'check', "
    From an ESX shell, run the following command:

    # esxcli system account list

    or

    From a PowerCLI command prompt while connected to the ESX host, run the following commands:

    $esxcli = Get-EsxCli -v2
    $esxcli.system.account.list.Invoke() | Where-Object {$_.UserID -eq 'dcui'}

    If shell access is not disabled for the dcui account, this is a finding.
  "
  desc 'fix', "
    From an ESX shell, run the following command:

    # esxcli system account set -i dcui -s false

    or

    From a PowerCLI command prompt while connected to the ESX host, run the following commands:

    $esxcli = Get-EsxCli -v2
    $arguments = $esxcli.system.account.set.CreateArgs()
    $arguments.id = \"dcui\"
    $arguments.shellaccess = \"false\"
    $esxcli.system.account.set.invoke($arguments)
  "
  impact 0.5
  tag severity: 'medium'
  tag gtitle: 'SRG-OS-000480-VMM-002000'
  tag gid: 'V-VCFE-9X-000237'
  tag rid: 'SV-VCFE-9X-000237'
  tag stig_id: 'VCFE-9X-000237'
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
      command = "$vmhost = Get-VMHost -Name #{vmhost}; $esxcli = Get-EsxCli -VMHost $vmhost -V2; $esxcli.system.account.list.Invoke() | Where-Object {$_.UserID -eq 'dcui'} | Select-Object -ExpandProperty Shellaccess"
      describe powercli_command(command) do
        its('stdout.strip') { should cmp 'false' }
      end
    end
  end
end
