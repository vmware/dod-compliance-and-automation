control "ESXI-67-000068" do
  title "All ESXi host-connected virtual switch VLANs must be fully documented
and have only the required VLANs."
  desc  "When defining a physical switch port for trunk mode, only specified
VLANs must be configured on the VLAN trunk link. The risk with not fully
documenting all VLANs on the vSwitch is that it is possible that a physical
trunk port might be configured without needed VLANs, or with unneeded VLANs,
potentially enabling an administrator to either accidentally or maliciously
connect a VM to an unauthorized VLAN."
  impact 0.5
  tag severity: "CAT II"
  tag gtitle: "SRG-OS-000480-VMM-002000"
  tag rid: "ESXI-67-000068"
  tag stig_id: "ESXI-67-000068"
  tag cci: "CCI-000366"
  tag nist: ["CM-6 b", "Rev_4"]
  desc 'check', "Note that this check refers to an entity outside the physical
scope of the ESXi server system. The configuration of upstream physical
switches must be documented to ensure that unneeded VLANs are configured for
all physical ports connected to ESXi hosts. Inspect the documentation and
verify that the documentation is updated on an organization defined frequency
and/or whenever modifications are made to either ESXi hosts or the upstream
physical switches. Alternatively, log in to the physical switch and verify that
only needed VLANs are configured for all physical ports connected to ESXi hosts.

If the physical switch's configuration is trunked VLANs that are not used by
ESXi for all physical ports connected to ESXi hosts, this is a finding."
  desc 'fix', "Note that this check refers to an entity outside the scope of the
ESXi server system.

Remove any VLANs trunked across physical ports connected to ESXi hosts that are
not in use."

  describe "" do
    skip 'Manual verification is required for this control'
  end

end

