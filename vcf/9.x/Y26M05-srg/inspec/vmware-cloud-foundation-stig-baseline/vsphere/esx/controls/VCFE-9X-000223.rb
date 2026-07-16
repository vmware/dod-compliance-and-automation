control 'VCFE-9X-000223' do
  title 'The ESX host must restrict the use of Virtual Guest Tagging (VGT) on standard switches.'
  desc  "
    When a port group is set to VLAN 4095, the vSwitch passes all network frames to the attached virtual machines (VMs) without modifying the VLAN tags. In vSphere, this is referred to as VGT. The VM must process the VLAN information itself via an 802.1Q driver in the operating system.

    VLAN 4095 must only be implemented if the attached VMs have been specifically authorized and are capable of managing VLAN tags themselves. If VLAN 4095 is enabled inappropriately, it may cause denial of service or allow a VM to interact with traffic on an unauthorized VLAN.
  "
  desc  'rationale', ''
  desc  'check', "
    This control addresses ESX standard switches. Distributed switches are addressed in the vCenter STIG. If there is no standard switch on the ESX host, this is not applicable.

    From the vSphere Client, go to Hosts and Clusters.

    Select the ESX Host >> Configure >> Networking >> Virtual Switches.

    For each standard switch, review the \"VLAN ID\" on each port group and verify it is not set to \"4095\".

    or

    From a PowerCLI command prompt while connected to the ESX host, run the following command:

    Get-VirtualPortGroup | Select Name, VLanID

    If any port group is configured with VLAN 4095 and is not documented as a needed exception, this is a finding.
  "
  desc 'fix', "
    From the vSphere Client, go to Hosts and Clusters.

    Select the ESX Host >> Configure >> Networking >> Virtual Switches.

    For each port group on a standard switch that is configured to a native VLAN, click the ellipse (...) button next to the port group.

    Click \"Edit Settings\". On the \"Properties\" tab, change the \"VLAN ID\" to an appropriate VLAN ID. Click \"OK\".

    or

    From a PowerCLI command prompt while connected to the ESX host, run the following command:

    Get-VirtualPortGroup -Name \"portgroup name\" | Set-VirtualPortGroup -VLanId \"New VLAN#\"
  "
  impact 0.5
  tag severity: 'medium'
  tag gtitle: 'SRG-OS-000480-VMM-002000'
  tag gid: 'V-VCFE-9X-000223'
  tag rid: 'SV-VCFE-9X-000223'
  tag stig_id: 'VCFE-9X-000223'
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
      command = "Get-VMHost -Name #{vmhost} | Get-VirtualPortGroup | Select-Object -ExpandProperty VlanId"
      describe powercli_command(command) do
        its('stdout.strip') { should_not match '4095' }
      end
    end
  end
end
