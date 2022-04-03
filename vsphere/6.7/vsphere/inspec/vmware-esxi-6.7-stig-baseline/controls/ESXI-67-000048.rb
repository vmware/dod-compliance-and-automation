control 'ESXI-67-000048' do
  title "The ESXi host must protect the confidentiality and integrity of
transmitted information by isolating vMotion traffic."
  desc  "While encrypted vMotion is available now, vMotion traffic should still
be sequestered from other traffic to further protect it from attack. This
network must be only be accessible to other ESXi hosts preventing outside
access to the network."
  desc  'rationale', ''
  desc  'check', "
    Verify the vMotion VMKernel port group is in a dedicated VLAN, which can be
on a common standard or distributed virtual switch as long as the vMotion VLAN
is not shared by any other function and is not routed to anything but ESXi
hosts.

    For environments that do not use vCenter server to manage ESXi, this is Not
Applicable.

    The check for this will be unique per environment.

    From the vSphere Client, select the ESXi host and go to Configuration >>
Networking.

    Review the VLAN associated with the vMotion VMkernel(s) and verify it is
dedicated for that purpose and logically separated from other functions.

    If long distance or cross-vCenter vMotion is used, the vMotion network can
be routable but must be accessible to only the intended ESXi hosts.

    If the vMotion port group is not on an isolated VLAN and/or is routable to
systems other than ESXi hosts, this is a finding.
  "
  desc 'fix', "
    Configuration of the vMotion VMkernel will be unique to each environment.

    As an example, to modify the IP address and VLAN information to the correct
network on a distributed switch, do the following:

    From the vSphere Client, go to Networking >> Select a distributed switch >>
Select a port group >> Configure >> Settings >> Edit >> VLAN.

    Change the \"VLAN Type\" to \"VLAN\" and change the \"VLAN ID\" to a
network allocated and dedicated to vMotion traffic exclusively.
  "
  impact 0.5
  tag severity: 'medium'
  tag gtitle: 'SRG-OS-000423-VMM-001700'
  tag gid: 'V-239303'
  tag rid: 'SV-239303r674838_rule'
  tag stig_id: 'ESXI-67-000048'
  tag fix_id: 'F-42495r674837_fix'
  tag cci: ['CCI-002418']
  tag nist: ['SC-8']

  describe 'This check is a manual or policy based check' do
    skip 'This must be reviewed manually'
  end
end
