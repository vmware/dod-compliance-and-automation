control "ESXI-67-000049" do
  title "The ESXi host must protect the confidentiality and integrity of
transmitted information by protecting ESXi management traffic."
  desc  "The vSphere management network provides access to the vSphere
management interface on each component. Services running on the management
interface provide an opportunity for an attacker to gain privileged access to
the systems. Any remote attack most likely would begin with gaining entry to
this network."
  impact 0.5
  tag severity: "CAT II"
  tag gtitle: "SRG-OS-000423-VMM-001700"
  tag rid: "ESXI-67-000049"
  tag stig_id: "ESXI-67-000049"
  tag cci: "CCI-002418"
  tag nist: ["SC-8", "Rev_4"]
  desc 'check', "The Management VMkernel port group must be on a dedicated VLAN
that can be on a common standard or distributed virtual switch as long as the
Management VLAN is not shared by any other function and it not accessible to
anything other than management related functions such as vCenter.  The check
for this will be unique per environment.

From the vSphere Client select the ESXi host and go to Configure >> Networking
and review the VLAN associated with the Management VMkernel and verify they are
dedicated for that purpose and are logically separated from other functions.

If the network segment is accessible, except to networks where other
management-related entities are located such as vCenter, this is a finding."
  desc 'fix', "From the vSphere Client select the ESXi host and go to Configure >>
Networking >> VMkernel adapters. Select the Management VMkernel and click Edit
>> On the Port properties tab uncheck everything but \"Management.
On the IP Settings tab >> Enter the appropriate IP address and subnet
information and click OK. Set the appropriate VLAN ID >> Configure >>
Networking >> Virtual switches. Select the Management portgroup and click Edit
>> On the properties tab, enter the appropriate VLAN ID and click OK."

  describe "" do
    skip 'Manual verification is required for this control'
  end

end

