control 'ESXI-70-000023' do
  title 'The ESXi host Secure Shell (SSH) daemon must be configured to not allow X11 forwarding.'
  desc 'X11 forwarding over SSH allows for the secure remote execution of X11-based applications. This feature can increase the attack surface of an SSH connection.'
  desc 'check', 'From an ESXi shell, run the following command:

# /usr/lib/vmware/openssh/bin/sshd -T|grep x11forwarding

Expected result:

x11forwarding no

If the output does not match the expected result, this is a finding.'
  desc 'fix', 'From an ESXi shell, add or correct the following line in "/etc/ssh/sshd_config":

X11Forwarding no'
  impact 0.5
  tag check_id: 'C-60067r885955_chk'
  tag severity: 'medium'
  tag gid: 'V-256392'
  tag rid: 'SV-256392r885957_rule'
  tag stig_id: 'ESXI-70-000023'
  tag gtitle: 'SRG-OS-000480-VMM-002000'
  tag fix_id: 'F-60010r885956_fix'
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']

  describe 'This check is a manual or policy based check' do
    skip 'This must be reviewed manually'
  end
end
