control 'ESXI-67-000067' do
  title "All ESXi host-connected physical switch ports must be configured with
spanning tree disabled."
  desc  "Since VMware virtual switches do not support STP, the ESXi
host-connected physical switch ports must have portfast configured if spanning
tree is enabled to avoid loops within the physical switch network. If these are
not set, potential performance and connectivity issues might arise."
  desc  'rationale', ''
  desc  'check', "
    Note that this check refers to an entity outside the physical scope of the
ESXi server system. The configuration of upstream physical switches must be
documented to ensure that spanning tree protocol is disabled and/or portfast is
configured for all physical ports connected to ESXi hosts.

    Inspect the documentation and verify that the documentation is updated
according to an organization-defined frequency and/or whenever modifications
are made to either ESXi hosts or the upstream physical switches.

    Alternatively, log in to the physical switch and verify that spanning tree
protocol is disabled and/or portfast is configured for all physical ports
connected to ESXi hosts.

    If the physical switch's spanning tree protocol is not disabled or portfast
is not configured for all physical ports connected to ESXi hosts, this is a
finding.
  "
  desc 'fix', "
    Note that this check refers to an entity outside the scope of the ESXi
server system.

    Document the upstream physical switch configuration for spanning tree
protocol disablement and/or portfast configuration for all physical ports
connected to ESXi hosts.

    Log in to the physical switch(es) and disable spanning tree protocol and/or
configure portfast for all physical ports connected to ESXi hosts.

    Update the documentation on an organization defined frequency or whenever
modifications are made to either ESXi hosts or the upstream physical switches.
  "
  impact 0.3
  tag severity: 'low'
  tag gtitle: 'SRG-OS-000480-VMM-002000'
  tag gid: 'V-239321'
  tag rid: 'SV-239321r674892_rule'
  tag stig_id: 'ESXI-67-000067'
  tag fix_id: 'F-42513r674891_fix'
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']

  describe 'This check is a manual or policy based check' do
    skip 'This must be reviewed manually'
  end
end
