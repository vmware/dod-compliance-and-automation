control 'VCFE-9X-000217' do
  title 'The ESX host must configure the firewall to restrict access to services running on the host.'
  desc  'Unrestricted access to services running on an ESX host can expose a host to outside attacks and unauthorized access. Reduce the risk by configuring the ESX firewall to only allow access from authorized networks.'
  desc  'rationale', ''
  desc  'check', "
    From the vSphere Client, go to Hosts and Clusters.

    Select the ESX Host >> Configure >> System >> Firewall.

    Under the \"Allowed IP addresses\" column, review the allowed IPs for each service.

    Check this for \"Incoming\" and \"Outgoing\" sections.

    or

    From a PowerCLI command prompt while connected to the ESX host, run the following command:

    Get-VMHost | Get-VMHostFirewallException | Where {($_.Enabled -eq $true) -and ($_.ExtensionData.IpListUserConfigurable -eq $true)} | Select Name,Enabled,@{N=\"AllIPEnabled\";E={$_.ExtensionData.AllowedHosts.AllIP}},@{N=\"AllIPUserConfigurable\";E={$_.ExtensionData.IpListUserConfigurable}}

    If \"Allow connections from any IP address\" is configured on a user-configurable enabled service, this is a finding.

    Note: In vSphere 8 U2 firewall rules were categorized as user or system owned for both enabling/disabling and configuring the allowed IP addresses. This control is only applicable for rules in which a user can configure the allowed IP addresses.
  "
  desc 'fix', "
    From the vSphere Client, go to Hosts and Clusters.

    Select the ESX Host >> Configure >> System >> Firewall.

    Click \"Edit...\". For each user-configurable enabled service, uncheck the check box to \"Allow connections from any IP address\" and input the site-specific network(s) required.

    The following example formats are acceptable:

    192.168.0.0/24
    192.168.1.2, 2001::1/64
    fd3e:29a6:0a81:e478::/64

    or

    From a PowerCLI command prompt while connected to the ESX host, run the following commands:

    $esxcli = Get-EsxCli -v2
    #This disables the allow all rule for the target service. The sshServer service is the target in this example.
    $arguments = $esxcli.network.firewall.ruleset.set.CreateArgs()
    $arguments.rulesetid = \"sshServer\"
    $arguments.allowedall = $false
    $esxcli.network.firewall.ruleset.set.Invoke($arguments)

    #Next add the allowed IPs for the service. Note that executing the \"vSphere Web Client\" service this way may disable access but may be done through vCenter or through the console.
    $arguments = $esxcli.network.firewall.ruleset.allowedip.add.CreateArgs()
    $arguments.rulesetid = \"sshServer\"
    $arguments.ipaddress = \"10.0.0.0/8\"
    $esxcli.network.firewall.ruleset.allowedip.add.Invoke($arguments)

    This must be done for each user-configurable enabled service.
  "
  impact 0.5
  tag severity: 'medium'
  tag gtitle: 'SRG-OS-000480-VMM-002000'
  tag gid: 'V-VCFE-9X-000217'
  tag rid: 'SV-VCFE-9X-000217'
  tag stig_id: 'VCFE-9X-000217'
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
      rules = powercli_command("Get-VMHost -Name #{vmhost} | Get-VMHostFirewallException | Where {($_.Enabled -eq $true) -and ($_.ExtensionData.IpListUserConfigurable -eq $true)} | Select-Object -ExpandProperty Name").stdout.gsub("\r\n", "\n").split("\n")
      rules.each do |rule|
        command = "(Get-VMHost -Name #{vmhost} | Get-VMHostFirewallException -Name '#{rule}').ExtensionData.AllowedHosts.AllIP"
        result = powercli_command(command).stdout.strip
        describe "Firewall rule for Service: #{rule} on VMhost: #{vmhost} allow all IPs" do
          subject { result }
          it { should cmp 'False' }
        end
      end
    end
  end
end
