control 'ESXI-67-000049' do
  title "The ESXi host must protect the confidentiality and integrity of
transmitted information by protecting ESXi management traffic."
  desc  "The vSphere management network provides access to the vSphere
management interface on each component. Services running on the management
interface provide an opportunity for an attacker to gain privileged access to
the systems. Any remote attack most likely would begin with gaining entry to
this network."
  desc  'rationale', ''
  desc  'check', "
    Verify the Management VMkernel port group is on a dedicated VLAN, which can
be on a common standard or distributed virtual switch as long as the Management
VLAN is not shared by any other function and is not accessible to anything
other than management-related functions such as vCenter.

    The check for this will be unique per environment.

    From the vSphere Client, select the ESXi host and go to Configure >>
Networking.

    Review the VLAN associated with the Management VMkernel and verify it is
dedicated for that purpose and is logically separated from other functions.

    If the network segment is accessible, except to networks where other
management-related entities such as vCenter are located, this is a finding.
  "
  desc 'fix', "
    From the vSphere Client, select the ESXi host and go to Configure >>
Networking >> VMkernel adapters.

    Select the Management VMkernel and click \"Edit\".

    On the Port properties tab, uncheck everything but \"Management.”

    On the IP Settings tab, enter the appropriate IP address and subnet
information and click \"OK\".

    Set the appropriate VLAN ID >> Configure >> Networking >> Virtual switches.

    Select the Management portgroup and click \"Edit\".

    On the properties tab, enter the appropriate VLAN ID and click \"OK\".
  "
  impact 0.5
  tag severity: 'medium'
  tag gtitle: 'SRG-OS-000423-VMM-001700'
  tag gid: 'V-239304'
  tag rid: 'SV-239304r674841_rule'
  tag stig_id: 'ESXI-67-000049'
  tag fix_id: 'F-42496r674840_fix'
  tag cci: ['CCI-002418']
  tag nist: ['SC-8']

  describe 'This check is a manual or policy based check' do
    skip 'This must be reviewed manually'
  end
end
