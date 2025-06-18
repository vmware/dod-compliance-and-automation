control 'VCFE-9X-000216' do
  title 'The ESX host must configure the firewall to block network traffic by default.'
  desc  'In addition to service-specific firewall rules, ESX has a default firewall rule policy to allow or deny incoming and outgoing traffic. Reduce the risk of attack by ensuring this is set to deny incoming and outgoing traffic.'
  desc  'rationale', ''
  desc  'check', "
    From an ESX shell, run the following command:

    # esxcli network firewall get

    or

    From a PowerCLI command prompt while connected to the ESX host, run the following commands:

    $esxcli = Get-EsxCli -v2
    $esxcli.network.firewall.get.invoke()

    If the \"Default Action\" does not equal \"DROP\", this is a finding.
    If \"Enabled\" does not equal \"true\", this is a finding.
  "
  desc 'fix', "
    From an ESX shell, run the following command:

    # esxcli network firewall set --default-action false --enabled true

    or

    From a PowerCLI command prompt while connected to the ESX host, run the following commands:

    $esxcli = Get-EsxCli -v2
    $arguments = $esxcli.network.firewall.set.CreateArgs()
    $arguments.enabled = $true
    $arguments.defaultaction = $false
    $esxcli.network.firewall.set.Invoke($arguments)
  "
  impact 0.5
  tag severity: 'medium'
  tag gtitle: 'SRG-OS-000480-VMM-002000'
  tag gid: 'V-VCFE-9X-000216'
  tag rid: 'SV-VCFE-9X-000216'
  tag stig_id: 'VCFE-9X-000216'
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
      command1 = "$vmhost = Get-VMHost -Name #{vmhost}; $esxcli = Get-EsxCli -VMHost $vmhost -V2; $esxcli.network.firewall.get.invoke() | Select-Object -ExpandProperty Enabled"
      describe powercli_command(command1) do
        its('stdout.strip') { should cmp 'true' }
      end
      command2 = "$vmhost = Get-VMHost -Name #{vmhost}; $esxcli = Get-EsxCli -VMHost $vmhost -V2; $esxcli.network.firewall.get.invoke() | Select-Object -ExpandProperty DefaultAction"
      describe powercli_command(command2) do
        its('stdout.strip') { should cmp 'DROP' }
      end
    end
  end
end
