control 'ESXI-70-000012' do
  title 'The ESXi host SSH daemon must ignore .rhosts files.'
  desc  'SSH trust relationships mean a compromise on one host can allow an attacker to move trivially to other hosts. SSH can emulate the behavior of the obsolete rsh command in allowing users to enable insecure access to their accounts via ".rhosts" files.'
  desc  'rationale', ''
  desc  'check', "
    From an ESXi shell, run the following command(s):

    # /usr/lib/vmware/openssh/bin/sshd -T|grep ignorerhosts

    Expected result:

    ignorerhosts yes

    If the output does not match the expected result, this is a finding.
  "
  desc 'fix', "
    From an ESXi shell, run the following command(s): add or correct the following line in \"/etc/ssh/sshd_config\":

    IgnoreRhosts yes
  "
  impact 0.5
  tag severity: 'medium'
  tag gtitle: 'SRG-OS-000107-VMM-000530'
  tag gid: nil
  tag rid: nil
  tag stig_id: 'ESXI-70-000012'
  tag cci: ['CCI-000767']
  tag nist: ['IA-2 (3)']

  describe 'This check is a manual or policy based check' do
    skip 'This must be reviewed manually'
  end
end
