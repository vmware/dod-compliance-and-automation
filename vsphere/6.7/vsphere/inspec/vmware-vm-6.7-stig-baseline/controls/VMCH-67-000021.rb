control "VMCH-67-000021" do
  title "Use of the virtual machine console must be minimized."
  desc  "The VM console enables a connection to the console of a virtual
machine, in effect seeing what a monitor on a physical server would show. The
VM console also provides power management and removable device connectivity
controls, which might potentially allow a malicious user to bring down a
virtual machine. In addition, it also has a performance impact on the service
console, especially if many VM console sessions are open simultaneously."
  impact 0.5
  tag severity: "CAT II"
  tag gtitle: "SRG-OS-000480-VMM-002000"
  tag gid: nil
  tag rid: "VMCH-67-000021"
  tag stig_id: "VMCH-67-000021"
  tag cci: "CCI-000366"
  tag nist: ["CM-6 b", "Rev_4"]
  desc 'check', "Remote management services, such as terminal services and SSH,
must be used to interact with virtual machines. VM console access should only
be granted when remote management services are unavailable or insufficient to
perform necessary management tasks.

Ask the SA if a VM console is used to perform VM management tasks, other than
for troubleshooting VM issues.

If a VM console is used to perform VM management tasks, other than for
troubleshooting VM issues, this is a finding.

If SSH and/or terminal management services are exclusively used to perform
management tasks, this is not a finding."
  desc 'fix', "Develop a policy prohibiting the use of a VM console for performing
management services. This policy should include procedures for the use of SSH
and Terminal Management services for VM management. Where SSH and Terminal
Management services prove insufficient to troubleshoot a VM, access to the VM
console may be temporarily granted."

  describe "This check is a manual or policy based check" do
    skip "This must be reviewed manually"
  end

end

