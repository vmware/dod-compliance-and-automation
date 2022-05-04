control 'ESXI-70-000090' do
  title 'The ESXi host rhttpproxy daemon must use FIPS 140-2 validated cryptographic modules to protect the confidentiality of remote access sessions.'
  desc  'ESXi runs a reverse proxy service called rhttpproxy that front ends internal services and APIs over one HTTPS port by redirecting virtual paths to localhost ports. This proxy implements a FIPS 140-2 validated OpenSSL crypographic module that is in FIPS mode by default. This configuration must be validated and maintained in order to protect the traffic that rhttpproxy manages.'
  desc  'rationale', ''
  desc  'check', "
    From an ESXi shell, run the following command(s):

    # esxcli system security fips140 rhttpproxy get

    or

    From a PowerCLI command prompt while connected to the ESXi host, run the following command(s):

    $esxcli = Get-EsxCli -v2
    $esxcli.system.security.fips140.rhttpproxy.get.invoke()

    Expected result:

    Enabled: true

    If the output does not match the expected result, this is a finding.
  "
  desc 'fix', "
    From an ESXi shell, run the following command(s):

    # esxcli system security fips140 rhttpproxy set -e true

    or

    From a PowerCLI command prompt while connected to the ESXi host, run the following command(s):

    $esxcli = Get-EsxCli -v2
    $arguments = $esxcli.system.security.fips140.rhttpproxy.set.CreateArgs()
    $arguments.enable = $true
    $esxcli.system.security.fips140.rhttpproxy.set.Invoke($arguments)
  "
  impact 0.5
  tag severity: 'medium'
  tag gtitle: 'SRG-OS-000033-VMM-000140'
  tag gid: nil
  tag rid: nil
  tag stig_id: 'ESXI-70-000090'
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
      command = "$vmhost = Get-VMHost -Name #{vmhost}; $esxcli = Get-EsxCli -VMHost $vmhost -V2; $esxcli.system.security.fips140.rhttpproxy.get.invoke() | Select-Object -ExpandProperty Enabled"
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
