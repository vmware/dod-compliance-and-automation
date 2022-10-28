control 'ESXI-70-000065' do
  title 'All port groups on standard switches must not be configured to VLAN values reserved by upstream physical switches.'
  desc  'Certain physical switches reserve certain VLAN IDs for internal purposes and often disallow traffic configured to these values. For example, Cisco Catalyst switches typically reserve VLANs 1001–1024 and 4094, while Nexus switches typically reserve 3968–4094. Check with the documentation for your specific switch. Using a reserved VLAN might result in a denial of service on the network.'
  desc  'rationale', ''
  desc  'check', "
    Note: This control addresses ESXi standard switches. Distributed switches are addressed in the vCenter STIG. If there is no standard switch on the ESXi host, this is Not Applicable.

    From the vSphere Client go to Hosts and Clusters >> Select the ESXi Host >> Configure >> Networking >> Virtual switches.

    For each standard switch, review the \"VLAN ID\" on each port group and verify it is not set to a reserved VLAN ID.

    or

    From a PowerCLI command prompt while connected to the ESXi host, run the following command:

    Get-VirtualPortGroup -Standard | Select Name, VLanId

    If any port group is configured with a reserved VLAN ID, this is a finding.
  "
  desc 'fix', "
    From the vSphere Client go to Hosts and Clusters >> Select the ESXi Host >> Configure >> Networking >> Virtual switches.

    For each port group on a standard switch that is configured to a reserved VLAN, click the '...' button next to the port group.

    Click \"Edit Settings\". On the \"Properties\" tab, change the \"VLAN ID\" to a an appropriate VLAN ID and click \"OK\".

    or

    From a PowerCLI command prompt while connected to the ESXi host, run the following command:

    Get-VirtualPortGroup -Name \"portgroup name\" | Set-VirtualPortGroup -VLanId \"New VLAN#\"
  "
  impact 0.5
  tag severity: 'medium'
  tag gtitle: 'SRG-OS-000480-VMM-002000'
  tag gid: nil
  tag rid: nil
  tag stig_id: 'ESXI-70-000065'
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
    vlanlist = ['1001', '1024', '3968', '4047', '4094']
    vmhosts.each do |vmhost|
      command = "Get-VMHost -Name #{vmhost} | Get-VirtualPortGroup -Standard | Select-Object -ExpandProperty VlanId"
      result = powercli_command(command).stdout.split("\r\n")
      describe result do
        it { should_not be_in vlanlist }
      end
    end
  else
    describe 'No hosts found!' do
      skip 'No hosts found...skipping tests'
    end
  end
end
