control 'ESXI-67-000064' do
  title "For the ESXi host, all port groups must not be configured to VLAN 4095
unless Virtual Guest Tagging (VGT) is required."
  desc  "When a port group is set to VLAN 4095, this activates VGT mode. In
this mode, the vSwitch passes all network frames to the guest VM without
modifying the VLAN tags, leaving it up to the guest to deal with them. VLAN
4095 should be used only if the guest has been specifically configured to
manage VLAN tags itself. If VGT is enabled inappropriately, it might cause
denial of service or allow a guest VM to interact with traffic on an
unauthorized VLAN."
  desc  'rationale', ''
  desc  'check', "
    From the vSphere Client, select the ESXi host and go to Configure >>
Networking >> Virtual switches.

    For each virtual switch, review the port group VLAN tags and verify they
are not set to 4095.

    or

    From a PowerCLI command prompt while connected to the ESXi host, run the
following command:

    Get-VirtualPortGroup | Select Name, VLanID

    If any port group is configured with VLAN 4095 and is not documented as a
needed exception, this is a finding.
  "
  desc 'fix', "
    From the vSphere Client, select the ESXi host and go to Configure >>
Networking >> Virtual switches.

    Highlight a port group where VLAN ID is set to 4095 and click Edit settings
(dots).

    Change the VLAN ID to an appropriate VLAN and click \"OK\".

    or

    From a PowerCLI command prompt while connected to the ESXi host, run the
following command:

    Get-VirtualPortGroup -Name \"portgroup name\" | Set-VirtualPortGroup
-VLanId \"New VLAN#\"
  "
  impact 0.5
  tag severity: 'medium'
  tag gtitle: 'SRG-OS-000480-VMM-002000'
  tag gid: 'V-239318'
  tag rid: 'SV-239318r674883_rule'
  tag stig_id: 'ESXI-67-000064'
  tag fix_id: 'F-42510r674882_fix'
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']

  command = "(Get-VMHost -Name #{input('vmhostName')}) | Get-VirtualPortGroup | Select-Object -ExpandProperty VlanId"
  describe powercli_command(command) do
    its('stdout.strip') { should_not match '4095' }
  end
end
