control 'VCSA-80-000273' do
  title 'The vCenter Server must not configure VLAN Trunking unless Virtual Guest Tagging (VGT) is required and authorized.'
  desc 'When a port group is set to VLAN Trunking, the vSwitch passes all network frames in the specified range to the attached virtual machines without modifying the virtual local area network (VLAN) tags. In vSphere, this is referred to as VGT.

The virtual machine must process the VLAN information itself via an 802.1Q driver in the operating system. VLAN Trunking must only be implemented if the attached virtual machines have been specifically authorized and are capable of managing VLAN tags themselves.

If VLAN Trunking is enabled inappropriately, it may cause a denial of service or allow a virtual machine to interact with traffic on an unauthorized VLAN.'
  desc 'check', 'If distributed switches are not used, this is not applicable.

From the vSphere Client, go to "Networking".

Select a distributed switch >> Select a distributed port group >> Configure >> Settings >> Policies.

Review the port group "VLAN Type" and "VLAN trunk range", if present.

or

From a PowerCLI command prompt while connected to the vCenter server, run the following command:

Get-VDPortgroup | Where {$_.ExtensionData.Config.Uplink -ne "True"} | Select Name,VlanConfiguration

If any port group is configured with "VLAN trunking" and is not documented as a needed exception (such as NSX appliances), this is a finding.

If any port group is authorized to be configured with "VLAN trunking" but is not configured with the most limited range necessary, this is a finding.'
  desc 'fix', 'From the vSphere Client, go to "Networking".

Select a distributed switch >> Select a distributed port group >> Configure >> Settings >> Policies.

Click "Edit".

Click the "VLAN" tab.

If "VLAN trunking" is not authorized, remove it by setting "VLAN type" to "VLAN" and configure an appropriate VLAN ID. Click "OK".

If "VLAN trunking" is authorized but the range is too broad, modify the range in the "VLAN trunk range" field to the minimum necessary and authorized range. An example range would be "1,3-5,8". Click "OK".

or

From a PowerCLI command prompt while connected to the vCenter server, run the following command to configure trunking:

Get-VDPortgroup "Portgroup Name" | Set-VDVlanConfiguration -VlanTrunkRange "<VLAN Range(s) comma separated>"

or

Run this command to configure a single VLAN ID:

Get-VDPortgroup "Portgroup Name" | Set-VDVlanConfiguration -VlanId "<New VLAN#>"'
  impact 0.5
  tag check_id: 'C-62680r934476_chk'
  tag severity: 'medium'
  tag gid: 'V-258940'
  tag rid: 'SV-258940r961863_rule'
  tag stig_id: 'VCSA-80-000273'
  tag gtitle: 'SRG-APP-000516'
  tag fix_id: 'F-62589r934477_fix'
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']

  command = 'Get-VDPortgroup | Where-Object {(($_.IsUplink -eq $false) -and ($_.VlanConfiguration -match "Trunk"))} | Select-Object -ExpandProperty Name'
  vdportgroups = powercli_command(command).stdout.gsub("\r\n", "\n").split("\n")

  if vdportgroups.empty?
    impact 0.0
    describe 'No distributed port groups found to check. This is not applicable.' do
      skip 'No distributed port groups found to check. This is not applicable.'
    end
  else
    vdportgroups.each do |vdpg|
      command = "(Get-VDPortgroup -Name \"#{vdpg}\").ExtensionData.Config.DefaultPortConfig.Vlan.VlanId.Start"
      describe powercli_command(command) do
        its('stdout.strip') { should_not cmp '0' }
      end
      command = "(Get-VDPortgroup -Name \"#{vdpg}\").ExtensionData.Config.DefaultPortConfig.Vlan.VlanId.End"
      describe powercli_command(command) do
        its('stdout.strip') { should_not cmp '4094' }
      end
    end
  end
end
