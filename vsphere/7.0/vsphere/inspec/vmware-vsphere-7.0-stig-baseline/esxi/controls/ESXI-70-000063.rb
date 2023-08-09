control 'ESXI-70-000063' do
  title 'All port groups on standard switches must be configured to a value other than that of the native virtual local area network (VLAN).'
  desc 'ESXi does not use the concept of native VLAN. Frames with a VLAN specified in the port group will have a tag, but frames with VLAN not specified in the port group are not tagged and therefore will belong to the native VLAN of the physical switch.

For example, frames on VLAN 1 from a Cisco physical switch will be untagged, because this is considered as the native VLAN. However, frames from ESXi specified as VLAN 1 will be tagged with a "1"; therefore, traffic from ESXi that is destined for the native VLAN will not be routed correctly (because it is tagged with a "1" instead of being untagged), and traffic from the physical switch coming from the native VLAN will not be visible (because it is not tagged).

If the ESXi virtual switch port group uses the native VLAN ID, traffic from those virtual machines (VMs) will not be visible to the native VLAN on the switch because the switch is expecting untagged traffic.'
  desc 'check', 'Note: This control addresses ESXi standard switches. Distributed switches are addressed in the vCenter STIG. If there is no standard switch on the ESXi host, this is not applicable.

From the vSphere Client, go to Hosts and Clusters.

Select the ESXi Host >> Configure >> Networking >> Virtual switches.

For each standard switch, review the "VLAN ID" on each port group. Verify they are not set to the native VLAN ID of the attached physical switch.

or

From a PowerCLI command prompt while connected to the ESXi host, run the following command:

Get-VirtualPortGroup -Standard | Select Name, VLanId

If any port group is configured with the native VLAN of the attached physical switch, this is a finding.'
  desc 'fix', 'From the vSphere Client, go to Hosts and Clusters.

Select the ESXi Host >> Configure >> Networking >> Virtual switches.

For each port group on a standard switch that is configured to a native VLAN, click the "..." button next to the port group.

Click "Edit Settings". On the "Properties" tab, change the "VLAN ID" to a non-native VLAN and click "OK".

or

From a PowerCLI command prompt while connected to the ESXi host, run the following command:

Get-VirtualPortGroup -Name "portgroup name" | Set-VirtualPortGroup -VLanId "New VLAN#"'
  impact 0.5
  tag check_id: 'C-60099r886051_chk'
  tag severity: 'medium'
  tag gid: 'V-256424'
  tag rid: 'SV-256424r886053_rule'
  tag stig_id: 'ESXI-70-000063'
  tag gtitle: 'SRG-OS-000480-VMM-002000'
  tag fix_id: 'F-60042r886052_fix'
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
        its('stdout.strip') { should_not match '1' }
      end
    end
  else
    describe 'No hosts found!' do
      skip 'No hosts found...skipping tests'
    end
  end
end
