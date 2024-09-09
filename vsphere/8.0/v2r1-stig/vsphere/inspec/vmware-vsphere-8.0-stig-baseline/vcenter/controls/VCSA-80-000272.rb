control 'VCSA-80-000272' do
  title 'The vCenter Server must configure all port groups to a value other than that of the native virtual local area network (VLAN).'
  desc 'ESXi does not use the concept of native VLAN. Frames with VLAN specified in the port group will have a tag, but frames with VLAN not specified in the port group are not tagged and therefore will end up belonging to native VLAN of the physical switch.

For example, frames on VLAN 1 from a Cisco physical switch will be untagged, because this is considered as the native VLAN. However, frames from ESXi specified as VLAN 1 will be tagged with a "1"; therefore, traffic from ESXi that is destined for the native VLAN will not be correctly routed (because it is tagged with a "1" instead of being untagged), and traffic from the physical switch coming from the native VLAN will not be visible (because it is not tagged).

If the ESXi virtual switch port group uses the native VLAN ID, traffic from those virtual machines will not be visible to the native VLAN on the switch, because the switch is expecting untagged traffic.'
  desc 'check', 'If distributed switches are not used, this is not applicable.

From the vSphere Client, go to "Networking".

Select a distributed switch >> Select a distributed port group >> Configure >> Settings >> Policies.

Review the port group VLAN tags and verify they are not set to the native VLAN ID of the attached physical switch.

or

From a PowerCLI command prompt while connected to the vCenter server, run the following command:

Get-VDPortgroup | select Name, VlanConfiguration

If any port group is configured with the native VLAN of the ESXi hosts attached physical switch, this is a finding.'
  desc 'fix', 'From the vSphere Client, go to "Networking".

Select a distributed switch >> Select a distributed port group >> Configure >> Settings >> Policies.

Click "Edit".

Click the "VLAN" tab.

Change the VLAN ID to a nonnative VLAN.

Click "OK".

or

From a PowerCLI command prompt while connected to the vCenter server, run the following command:

Get-VDPortgroup "portgroup name" | Set-VDVlanConfiguration -VlanId "New VLAN#"'
  impact 0.5
  tag check_id: 'C-62679r934473_chk'
  tag severity: 'medium'
  tag gid: 'V-258939'
  tag rid: 'SV-258939r961863_rule'
  tag stig_id: 'VCSA-80-000272'
  tag gtitle: 'SRG-APP-000516'
  tag fix_id: 'F-62588r934474_fix'
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']

  command = 'Get-VDPortgroup | Where-Object {$_.IsUplink -eq $false} | Select -ExpandProperty Name'
  vdportgroups = powercli_command(command).stdout.gsub("\r\n", "\n").split("\n")

  if vdportgroups.empty?
    impact 0.0
    describe 'No distributed port groups found. This is not applicable.' do
      skip 'No distributed port groups found. This is not applicable.'
    end
  else
    vdportgroups.each do |vdpg|
      command = "(Get-VDPortgroup -Name \"#{vdpg}\").ExtensionData.Config.DefaultPortConfig.Vlan.VlanId"
      describe powercli_command(command) do
        its('stdout.strip') { should_not cmp '1' }
      end
    end
  end
end
