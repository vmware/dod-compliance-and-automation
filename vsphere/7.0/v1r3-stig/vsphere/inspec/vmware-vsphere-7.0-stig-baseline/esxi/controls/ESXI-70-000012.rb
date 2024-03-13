control 'ESXI-70-000012' do
  title 'The ESXi host Secure Shell (SSH) daemon must ignore ".rhosts" files.'
  desc 'SSH trust relationships mean a compromise on one host can allow an attacker to move trivially to other hosts. SSH can emulate the behavior of the obsolete "rsh" command in allowing users to enable insecure access to their accounts via ".rhosts" files.'
  desc 'check', 'From an ESXi shell, run the following command:

# /usr/lib/vmware/openssh/bin/sshd -T|grep ignorerhosts

Expected result:

ignorerhosts yes

If the output does not match the expected result, this is a finding.'
  desc 'fix', 'From an ESXi shell, add or correct the following line in "/etc/ssh/sshd_config":

IgnoreRhosts yes'
  impact 0.5
  tag check_id: 'C-60060r885934_chk'
  tag severity: 'medium'
  tag gid: 'V-256385'
  tag rid: 'SV-256385r919018_rule'
  tag stig_id: 'ESXI-70-000012'
  tag gtitle: 'SRG-OS-000107-VMM-000530'
  tag fix_id: 'F-60003r918908_fix'
  tag cci: ['CCI-000767']
  tag nist: ['IA-2 (3)']

  describe 'This check is a manual or policy based check' do
    skip 'This must be reviewed manually'
  end
end
