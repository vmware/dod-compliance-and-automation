control 'ESXI-70-000021' do
  title 'The ESXi host Secure Shell (SSH) daemon must not allow compression or must only allow compression after successful authentication.'
  desc 'If compression is allowed in an SSH connection prior to authentication, vulnerabilities in the compression software could result in compromise of the system from an unauthenticated connection, potentially with root privileges.'
  desc 'check', 'From an ESXi shell, run the following command:

# /usr/lib/vmware/openssh/bin/sshd -T|grep compression

Expected result:

compression no

If the output does not match the expected result, this is a finding.'
  desc 'fix', 'From an ESXi shell, add or correct the following line in "/etc/ssh/sshd_config":

Compression no'
  impact 0.5
  tag check_id: 'C-60065r885949_chk'
  tag severity: 'medium'
  tag gid: 'V-256390'
  tag rid: 'SV-256390r885951_rule'
  tag stig_id: 'ESXI-70-000021'
  tag gtitle: 'SRG-OS-000480-VMM-002000'
  tag fix_id: 'F-60008r885950_fix'
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']

  describe 'This check is a manual or policy based check' do
    skip 'This must be reviewed manually'
  end
end
