control 'ESXI-70-000064' do
  title 'All port groups on standard switches must not be configured to VLAN 4095 unless Virtual Guest Tagging (VGT) is required.'
  desc  'When a port group is set to VLAN 4095, the vSwitch passes all network frames to the attached VMs without modifying the VLAN tags. In vSphere, this is referred to as Virtual Guest Tagging (VGT). The VM must process the VLAN information itself via an 802.1Q driver in the OS. VLAN 4095 must only be implemented if the attached VMs have been specifically authorized and are capable of managing VLAN tags themselves. If VLAN 4095 is enabled inappropriately, it may cause denial of service or allow a VM to interact with traffic on an unauthorized VLAN.'
  desc  'rationale', ''
  desc  'check', "
    Note: This control addresses ESXi standard switches. Distributed switches are addressed in the vCenter STIG. If there is no standard switch on the ESXi host, this is Not Applicable.

    From the vSphere Client go to Hosts and Clusters >> Select the ESXi Host >> Configure >> Networking >> Virtual switches.

    For each standard switch, review the \"VLAN ID\" on each port group and verify it is not set to \"4095\".

    or

    From a PowerCLI command prompt while connected to the ESXi host, run the following command:

    Get-VirtualPortGroup -Standard | Select Name, VLanID

    If any port group is configured with VLAN 4095 and is not documented as a needed exception, this is a finding.
  "
  desc 'fix', "
    From the vSphere Client go to Hosts and Clusters >> Select the ESXi Host >> Configure >> Networking >> Virtual switches.

    For each port group on a standard switch that is configured to a native VLAN, click the '...' button next to the port group.

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
  tag stig_id: 'ESXI-70-000064'
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
      command = "Get-VMHost -Name #{vmhost} | Get-VirtualPortGroup -Standard | Select-Object -ExpandProperty VlanId"
      describe powercli_command(command) do
        its('stdout.strip') { should_not match '4095' }
      end
    end
  else
    describe 'No hosts found!' do
      skip 'No hosts found...skipping tests'
    end
  end
end
