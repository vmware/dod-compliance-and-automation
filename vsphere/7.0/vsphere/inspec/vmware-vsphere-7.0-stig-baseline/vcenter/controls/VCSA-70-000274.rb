control 'VCSA-70-000274' do
  title 'The vCenter Server must not configure all port groups to VLAN values reserved by upstream physical switches.'
  desc  "
    Certain physical switches reserve certain VLAN IDs for internal purposes and often disallow traffic configured to these values. For example, Cisco Catalyst switches typically reserve VLANs 1001-1024 and 4094, while Nexus switches typically reserve 3968-4094.

    Check with the documentation for your specific switch. Using a reserved VLAN might result in a denial of service on the network.
  "
  desc  'rationale', ''
  desc  'check', "
    If distributed switches are not used, this is Not Applicable.

    From the vSphere Client, go to Networking >> Select a distributed switch >> Select a distributed port group >> Configure >> Settings >> Policies.

    Review the port group VLAN tags and verify that they are not set to a reserved VLAN ID.

    or

    From a PowerCLI command prompt while connected to the vCenter server, run the following command:

    Get-VDPortgroup | select Name, VlanConfiguration

    If any port group is configured with a reserved VLAN ID, this is a finding.
  "
  desc 'fix', "
    From the vSphere Client, go to Networking >> Select a distributed switch >> Select a distributed port group >> Configure >> Settings >> Policies.

    Click \"Edit\".

    Click the \"VLAN\" tab. Change the VLAN ID to an unreserved VLAN ID.

    Click \"OK\".

    or

    From a PowerCLI command prompt while connected to the vCenter server, run the following command:

    Get-VDPortgroup \"portgroup name\" | Set-VDVlanConfiguration -VlanId \"New VLAN#\"
  "
  impact 0.5
  tag severity: 'medium'
  tag gtitle: 'SRG-APP-000516'
  tag gid: nil
  tag rid: nil
  tag stig_id: 'VCSA-70-000274'
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']

  command = 'Get-VDPortgroup | Where-Object {$_.IsUplink -eq $false} | Select -ExpandProperty Name'
  vdportgroups = powercli_command(command).stdout.split("\n")

  if vdportgroups.empty?
    describe '' do
      skip 'No distributed port groups found to check.'
    end
  else
    vlanlist = ['1001', '1024', '3968', '4047', '4094']
    vdportgroups.each do |vdpg|
      command = "(Get-VDPortgroup -Name \"#{vdpg}\").ExtensionData.Config.DefaultPortConfig.Vlan.VlanId"
      describe powercli_command(command) do
        its('stdout.strip') { should_not be_in vlanlist }
      end
    end
  end
end
