control 'VMCH-70-000021' do
  title 'Use of the virtual machine (VM)  console must be minimized.'
  desc 'The VM console enables a connection to the console of a virtual machine, in effect seeing what a monitor on a physical server would show. The VM console also provides power management and removable device connectivity controls, which could allow a malicious user to bring down a VM. In addition, it impacts performance on the service console, especially if many VM console sessions are open simultaneously.'
  desc 'check', 'Remote management services, such as terminal services and Secure Shell (SSH), must be used to interact with VMs.

VM console access should only be granted when remote management services are unavailable or insufficient to perform necessary management tasks.

Ask the system administrator if a VM console is used to perform VM management tasks other than for troubleshooting VM issues.

If a VM console is used to perform VM management tasks other than for troubleshooting VM issues, this is a finding.

If SSH and/or terminal management services are exclusively used to perform management tasks, this is not a finding.'
  desc 'fix', 'Develop a policy prohibiting the use of a VM console for performing management services.

This policy should include procedures for the use of SSH and Terminal Management services for VM management.

Where SSH and Terminal Management services prove insufficient to troubleshoot a VM, access to the VM console may be granted temporarily.'
  impact 0.5
  tag check_id: 'C-60144r886448_chk'
  tag severity: 'medium'
  tag gid: 'V-256469'
  tag rid: 'SV-256469r886450_rule'
  tag stig_id: 'VMCH-70-000021'
  tag gtitle: 'SRG-OS-000480-VMM-002000'
  tag fix_id: 'F-60087r886449_fix'
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']

  describe 'This check is a manual or policy based check' do
    skip 'This must be reviewed manually'
  end
end
