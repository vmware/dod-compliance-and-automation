control 'ESXI-70-000016' do
  title 'The ESXi host Secure Shell (SSH) daemon must not permit user environment settings.'
  desc 'SSH environment options potentially allow users to bypass access restriction in some configurations. Users must not be able to present environment options to the SSH daemon.'
  desc 'check', 'From an ESXi shell, run the following command:

# /usr/lib/vmware/openssh/bin/sshd -T|grep permituserenvironment

Expected result:

permituserenvironment no

If the output does not match the expected result, this is a finding.'
  desc 'fix', 'From an ESXi shell, add or correct the following line in "/etc/ssh/sshd_config":

PermitUserEnvironment no'
  impact 0.5
  tag check_id: 'C-60063r885943_chk'
  tag severity: 'medium'
  tag gid: 'V-256388'
  tag rid: 'SV-256388r885945_rule'
  tag stig_id: 'ESXI-70-000016'
  tag gtitle: 'SRG-OS-000480-VMM-002000'
  tag fix_id: 'F-60006r885944_fix'
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']

  describe 'This check is a manual or policy based check' do
    skip 'This must be reviewed manually'
  end
end
