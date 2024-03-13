control 'ESXI-70-000015' do
  title 'The ESXi host Secure Shell (SSH) daemon must not allow authentication using an empty password.'
  desc 'Configuring this setting for the SSH daemon provides additional assurance that remote logon via SSH will require a password, even in the event of misconfiguration elsewhere.'
  desc 'check', 'From an ESXi shell, run the following command:

# /usr/lib/vmware/openssh/bin/sshd -T|grep permitemptypasswords

Expected result:

permitemptypasswords no

If the output does not match the expected result, this is a finding.'
  desc 'fix', 'From an ESXi shell, add or correct the following line in "/etc/ssh/sshd_config":

PermitEmptyPasswords no'
  impact 0.3
  tag check_id: 'C-60062r885940_chk'
  tag severity: 'low'
  tag gid: 'V-256387'
  tag rid: 'SV-256387r885942_rule'
  tag stig_id: 'ESXI-70-000015'
  tag gtitle: 'SRG-OS-000480-VMM-002000'
  tag fix_id: 'F-60005r885941_fix'
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']

  describe 'This check is a manual or policy based check' do
    skip 'This must be reviewed manually'
  end
end
