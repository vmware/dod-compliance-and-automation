control 'VCSA-70-000273' do
  title 'The vCenter Server must not configure VLAN Trunking unless Virtual Guest Tagging (VGT) is required and authorized.'
  desc  "
    When a port group is set to VLAN Trunking, the vSwitch passes all network frames in the specified range to the attached VMs without modifying the VLAN tags. In vSphere, this is referred to as Virtual Guest Tagging (VGT).

    The VM must process the VLAN information itself via an 802.1Q driver in the OS. VLAN Trunking must only be implemented if the attached VMs have been specifically authorized and are capable of managing VLAN tags themselves.

    If VLAN Trunking is enabled inappropriately, it may cause denial of service or allow a VM to interact with traffic on an unauthorized VLAN.
  "
  desc  'rationale', ''
  desc  'check', "
    If distributed switches are not used, this is Not Applicable.

    From the vSphere Client, go to Networking >> Select a distributed switch >> Select a distributed port group >> Configure >> Settings >> Policies.

    Review the port group \"VLAN Type\" and \"VLAN trunk range\", if present.

    or

    From a PowerCLI command prompt while connected to the vCenter server, run the following command:

    Get-VDPortgroup | Where {$_.ExtensionData.Config.Uplink -ne \"True\"} | Select Name,VlanConfiguration

    If any port group is configured with \"VLAN trunking\" and is not documented as a needed exception (such as NSX appliances), this is a finding.

    If any port group is authorized to be configured with \"VLAN trunking\" but is not configured with the most limited range necessary, this is a finding.
  "
  desc 'fix', "
    From the vSphere Client, go to Networking >> Select a distributed switch >> Select a distributed port group >> Configure >> Settings >> Policies.

    Click \"Edit\".

    Click the \"VLAN\" tab.

    If \"VLAN trunking\" is not authorized, remove it by setting \"VLAN type\" to \"VLAN\" and configure an appropriate VLAN ID. Click \"OK\".

    If \"VLAN trunking\" is authorized but the range is too broad, modify the range in the \"VLAN trunk range\" field to the minimum necessary and authorized range. An example range would be \"1,3-5,8\". Click \"OK\".

    or

    From a PowerCLI command prompt while connected to the vCenter server, run the following command to configure trunking:

    Get-VDPortgroup \"Portgroup Name\" | Set-VDVlanConfiguration -VlanTrunkRange \"<VLAN Range(s) comma separated>\"

    or

    Run this command to configure a single VLAN ID:

    Get-VDPortgroup \"Portgroup Name\" | Set-VDVlanConfiguration -VlanId \"<New VLAN#>\"
  "
  impact 0.5
  tag severity: 'medium'
  tag gtitle: 'SRG-APP-000516'
  tag gid: nil
  tag rid: nil
  tag stig_id: 'VCSA-70-000273'
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']

  command = 'Get-VDPortgroup | Where-Object {(($_.IsUplink -eq $false) -and ($_.VlanConfiguration -match "Trunk"))} | Select-Object -ExpandProperty Name'
  vdportgroups = powercli_command(command).stdout.split("\n")

  if vdportgroups.empty?
    describe '' do
      skip 'No distributed port groups found to check.'
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
