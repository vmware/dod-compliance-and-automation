control 'VCFE-9X-000206' do
  title 'The ESX host Secure Shell (SSH) daemon must be configured to only use FIPS 140-2 validated ciphers.'
  desc  'Use of weak or untested encryption algorithms undermines the purposes of utilizing encryption to protect data. ESX must implement cryptographic modules adhering to the higher standards approved by the federal government since this provides assurance they have been tested and validated.'
  desc  'rationale', ''
  desc  'check', "
    From an ESX shell, run the following command:

    # esxcli system ssh server config list -k ciphers

    or

    From a PowerCLI command prompt while connected to the ESX host, run the following commands:

    $esxcli = Get-EsxCli -v2
    $esxcli.system.ssh.server.config.list.invoke() | Where-Object {$_.Key -eq 'ciphers'}

    Expected result:

    ciphers aes256-gcm@openssh.com,aes128-gcm@openssh.com,aes256-ctr,aes192-ctr,aes128-ctr

    If the output matches the ciphers in the expected result or a subset thereof, this is not a finding.

    If the ciphers in the output contain any ciphers not listed in the expected result, this is a finding.
  "
  desc 'fix', "
    From an ESX shell, run the following command:

    # esxcli system ssh server config set -k ciphers -v aes256-gcm@openssh.com,aes128-gcm@openssh.com,aes256-ctr,aes192-ctr,aes128-ctr

    or

    From a PowerCLI command prompt while connected to the ESX host, run the following commands:

    $esxcli = Get-EsxCli -v2
    $arguments = $esxcli.system.ssh.server.config.set.CreateArgs()
    $arguments.keyword = 'ciphers'
    $arguments.value = 'aes256-gcm@openssh.com,aes128-gcm@openssh.com,aes256-ctr,aes192-ctr,aes128-ctr'
    $esxcli.system.ssh.server.config.set.Invoke($arguments)
  "
  impact 0.5
  tag severity: 'medium'
  tag gtitle: 'SRG-OS-000480-VMM-002000'
  tag gid: 'V-VCFE-9X-000206'
  tag rid: 'SV-VCFE-9X-000206'
  tag stig_id: 'VCFE-9X-000206'
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
      command = "$vmhost = Get-VMHost -Name #{vmhost}; $esxcli = Get-EsxCli -VMHost $vmhost -V2; $esxcli.system.ssh.server.config.list.invoke() | Where-Object {$_.Key -eq 'ciphers'} | Select-Object -ExpandProperty Value"
      describe powercli_command(command) do
        its('stdout.strip') { should cmp 'aes256-gcm@openssh.com,aes128-gcm@openssh.com,aes256-ctr,aes192-ctr,aes128-ctr' }
      end
    end
  end
end
