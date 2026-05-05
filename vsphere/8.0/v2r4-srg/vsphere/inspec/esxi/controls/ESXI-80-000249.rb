control 'ESXI-80-000249' do
  title 'The ESXi host must deny shell access for the dcui account.'
  desc 'The dcui user is used for process isolation for the DCUI itself. The account has shell access which can be deactivated to reduce attack surface.'
  desc 'check', "From an ESXi shell, run the following command:

# esxcli system account list

or

From a PowerCLI command prompt while connected to the ESXi host, run the following commands:

$esxcli = Get-EsxCli -v2
$esxcli.system.account.list.Invoke() | Where-Object {$_.UserID -eq 'dcui'}

If shell access is not disabled for the dcui account, this is a finding."
  desc 'fix', 'From an ESXi shell, run the following command:

# esxcli system account set -i dcui -s false

or

From a PowerCLI command prompt while connected to the ESXi host, run the following commands:

$esxcli = Get-EsxCli -v2
$arguments = $esxcli.system.account.set.CreateArgs()
$arguments.id = "dcui"
$arguments.shellaccess = "false"
$esxcli.system.account.set.invoke($arguments)'
  impact 0.5
  tag check_id: 'C-69899r1003582_chk'
  tag severity: 'medium'
  tag gid: 'V-265976'
  tag rid: 'SV-265976r1003584_rule'
  tag stig_id: 'ESXI-80-000249'
  tag gtitle: 'SRG-OS-000480-VMM-002000'
  tag fix_id: 'F-69802r1003583_fix'
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
      command = "$vmhost = Get-VMHost -Name #{vmhost}; $esxcli = Get-EsxCli -VMHost $vmhost -V2; $esxcli.system.account.list.Invoke() | Where-Object {$_.UserID -eq 'dcui'} | Select-Object -ExpandProperty Shellaccess"
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
