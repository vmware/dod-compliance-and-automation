control 'ESXI-80-000014' do
  title 'The ESXi host Secure Shell (SSH) daemon must use FIPS 140-2 validated cryptographic modules to protect the confidentiality of remote access sessions.'
  desc  "
    Without confidentiality protection mechanisms, unauthorized individuals may gain access to sensitive information via a remote access session.

    OpenSSH on the ESXi host ships with a FIPS 140-2 validated cryptographic module and it is enabled by default. For backward compatibility reasons, this can be disabled so this setting must be audited and corrected if necessary.
  "
  desc  'rationale', ''
  desc  'check', "
    From an ESXi shell, run the following command:

    # esxcli system security fips140 ssh get

    or

    From a PowerCLI command prompt while connected to the ESXi host, run the following commands:

    $esxcli = Get-EsxCli -v2
    $esxcli.system.security.fips140.ssh.get.invoke()

    Expected result:

    Enabled: true

    If the FIPS mode is not enabled for SSH, this is a finding.
  "
  desc 'fix', "
    From an ESXi shell, run the following command:

    # esxcli system security fips140 ssh set -e true

    or

    From a PowerCLI command prompt while connected to the ESXi host, run the following commands:

    $esxcli = Get-EsxCli -v2
    $arguments = $esxcli.system.security.fips140.ssh.set.CreateArgs()
    $arguments.enable = $true
    $esxcli.system.security.fips140.ssh.set.Invoke($arguments)
  "
  impact 0.7
  tag severity: 'high'
  tag gtitle: 'SRG-OS-000033-VMM-000140'
  tag gid: 'V-ESXI-80-000014'
  tag rid: 'SV-ESXI-80-000014'
  tag stig_id: 'ESXI-80-000014'
  tag cci: ['CCI-000068']
  tag nist: ['AC-17 (2)']

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
      command = "$vmhost = Get-VMHost -Name #{vmhost}; $esxcli = Get-EsxCli -VMHost $vmhost -V2; $esxcli.system.security.fips140.ssh.get.invoke() | Select-Object -ExpandProperty Enabled"
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
