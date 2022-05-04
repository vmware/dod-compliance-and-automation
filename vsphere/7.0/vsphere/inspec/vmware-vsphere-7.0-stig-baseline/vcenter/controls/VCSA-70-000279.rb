control 'VCSA-70-000279' do
  title 'The vCenter Server must protect the confidentiality and integrity of transmitted information by isolating IP-based storage traffic.'
  desc  "
    Virtual machines might share virtual switches and VLANs with the IP-based storage configurations. IP-based storage includes vSAN, iSCSI, and NFS. This configuration might expose IP-based storage traffic to unauthorized virtual machine users. IP-based storage frequently is not encrypted. It can be viewed by anyone with access to this network.

    To restrict unauthorized users from viewing the IP-based storage traffic, the IP-based storage network must be logically separated from the production traffic. Configuring the IP-based storage adaptors on separate VLANs or network segments from other VMkernels and Virtual Machines will limit unauthorized users from viewing the traffic.
  "
  desc  'rationale', ''
  desc  'check', "
    If IP-based storage is not used, this is Not Applicable.

    IP-Based storage (iSCSI, NFS, vSAN) VMkernel port groups must be in a dedicated VLAN that can be on a standard or distributed virtual switch that is logically separated from other traffic types.

    The check for this will be unique per environment.

    To check a standard switch, from the vSphere Client select the ESXi host and go to Configure >> Networking >> Virtual switches. Select a standard switch.

    For each storage port group (iSCSI, NFS, vSAN), select the port group and note the VLAN ID associated with each port group.

    Verify that it is dedicated to that purpose and is logically separated from other traffic types.

    To check a distributed switch, From the vSphere Client, go to Networking >> Select and expand a distributed switch.

    For each storage port group (iSCSI, NFS, vSAN), select the port group and navigate to the Summary tab.

    Note the VLAN ID associated with each port group and verify that it is dedicated to that purpose and is logically separated from other traffic types.

    If any IP-Based storage networks are not isolated from other traffic types, this is a finding.
  "
  desc 'fix', "
    Configuration of an IP-Based VMkernel will be unique to each environment.

    To configure VLANs and traffic types, do the following:

    Standard switch:

    From the vSphere Client select the ESXi host and go to Configure >> Networking >> VMkernel adapters.

    Select the Storage VMkernel (for any IP-based storage) Click \"Edit...\" >> Click the \"Port properties\" tab.

    Uncheck everything (unless vSAN).

    Click the IPv4 settings or IPv6 settings tab.

    Enter the appropriate IP address and subnet information.

    Click \"OK\".

    From the vSphere Client select the ESXi host and go to Configure >> Networking >> Virtual switches. Select a standard switch.

    For each storage port group (iSCSI, NFS, vSAN), select the port group and click \"...\" >> Click \"Edit Settings\" >> On the \"Properties\" tab, enter the appropriate VLAN ID and click \"OK\".

    Distributed switch:

    From the vSphere Client, go to Networking >> Select a distributed switch >> Configure >> Settings >> Topology.

    Select the Storage VMkernel (for any IP-based storage) Click \"...\". Click \"Edit Settings\".

    On the \"Port properties\" tab, uncheck everything (unless vSAN).

    Click the IPv4 settings or IPv6 settings tab.

    Enter the appropriate IP address and subnet information.

    Click \"OK\".

    From the vSphere Client, go to Networking >> Select and expand a distributed switch.

    For each storage port group (iSCSI, NFS, vSAN), select the port group and navigate to Configure >> Settings >> Properties.

    Click \"Edit\".

    Click the \"VLAN\" tab.

    Enter the appropriate VLAN type and ID and click OK.
  "
  impact 0.5
  tag severity: 'medium'
  tag gtitle: 'SRG-APP-000516'
  tag gid: nil
  tag rid: nil
  tag stig_id: 'VCSA-70-000279'
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']

  describe 'This check is a manual or policy based check' do
    skip 'This must be reviewed manually'
  end
end
