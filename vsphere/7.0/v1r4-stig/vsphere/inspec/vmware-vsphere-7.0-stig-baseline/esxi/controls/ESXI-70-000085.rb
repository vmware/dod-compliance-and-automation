control 'ESXI-70-000085' do
  title 'The ESXi host must enable strict x509 verification for SSL syslog endpoints.'
  desc %q(When sending syslog data to a remote host via SSL, the ESXi host is presented with the endpoint's SSL server certificate. In addition to trust verification, configured elsewhere, this "x509-strict" option performs additional validity checks on CA root certificates during verification.

These checks are generally not performed (CA roots are inherently trusted) and might cause incompatibilities with existing, misconfigured CA roots. The NIAP requirements in the Virtualization Protection Profile and Server Virtualization Extended Package, however, require even CA roots to pass validations.)
  desc 'check', 'If SSL is not used for the syslog target, this is not applicable.

From an ESXi shell, run the following command:

# esxcli system syslog config get|grep 509

or

From a PowerCLI command prompt while connected to the ESXi host, run the following commands:

$esxcli = Get-EsxCli -v2
$esxcli.system.syslog.config.get.invoke()|Select StrictX509Compliance

Expected result:

Strict X509Compliance: true

If the output does not match the expected result, this is a finding.'
  desc 'fix', 'From an ESXi shell, run the following commands:

# esxcli system syslog config set --x509-strict="true"
# esxcli system syslog reload

or

From a PowerCLI command prompt while connected to the ESXi host, run the following commands:

$esxcli = Get-EsxCli -v2
$arguments = $esxcli.system.syslog.config.set.CreateArgs()
$arguments.x509strict = $true
$esxcli.system.syslog.config.set.Invoke($arguments)
$esxcli.system.syslog.reload.Invoke()'
  impact 0.5
  tag check_id: 'C-60112r918920_chk'
  tag severity: 'medium'
  tag gid: 'V-256437'
  tag rid: 'SV-256437r919026_rule'
  tag stig_id: 'ESXI-70-000085'
  tag gtitle: 'SRG-OS-000480-VMM-002000'
  tag fix_id: 'F-60055r886091_fix'
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
      command = "$vmhost = Get-VMHost -Name #{vmhost}; $esxcli = Get-EsxCli -VMHost $vmhost -V2; $esxcli.system.syslog.config.get.invoke() | Select-Object -ExpandProperty StrictX509Compliance"
      describe powercli_command(command) do
        its('stdout.strip') { should cmp 'true' }
      end
    end
  else
    describe 'No hosts found!' do
      skip 'No hosts found...skipping tests'
    end
  end
end
