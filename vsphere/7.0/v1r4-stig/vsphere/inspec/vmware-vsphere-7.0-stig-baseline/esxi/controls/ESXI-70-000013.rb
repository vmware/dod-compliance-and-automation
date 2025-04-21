control 'ESXI-70-000013' do
  title 'The ESXi host Secure Shell (SSH) daemon must not allow host-based authentication.'
  desc %q(SSH trust relationships mean a compromise on one host can allow an attacker to move trivially to other hosts. SSH's cryptographic host-based authentication is more secure than ".rhosts" authentication because hosts are cryptographically authenticated. However, it is not recommended that hosts unilaterally trust one another, even within an organization.)
  desc 'check', 'From an ESXi shell, run the following command:

# /usr/lib/vmware/openssh/bin/sshd -T|grep hostbasedauthentication

Expected result:

hostbasedauthentication no

If the output does not match the expected result, this is a finding.'
  desc 'fix', 'From an ESXi shell, add or correct the following line in "/etc/ssh/sshd_config":

HostbasedAuthentication no'
  impact 0.5
  tag check_id: 'C-60061r885937_chk'
  tag severity: 'medium'
  tag gid: 'V-256386'
  tag rid: 'SV-256386r885939_rule'
  tag stig_id: 'ESXI-70-000013'
  tag gtitle: 'SRG-OS-000480-VMM-002000'
  tag fix_id: 'F-60004r885938_fix'
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']

  describe 'This check is a manual or policy based check' do
    skip 'This must be reviewed manually'
  end
end
