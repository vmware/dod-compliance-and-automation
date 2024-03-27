control 'ESXI-70-000027' do
  title 'The ESXi host Secure Shell (SSH) daemon must set a timeout interval on idle sessions.'
  desc 'Automatically logging out idle users guards against compromises via hijacked administrative sessions.'
  desc 'check', 'From an ESXi shell, run the following command:

# /usr/lib/vmware/openssh/bin/sshd -T|grep clientaliveinterval

Expected result:

clientaliveinterval 200

If the output does not match the expected result, this is a finding.'
  desc 'fix', 'From an ESXi shell, add or correct the following line in "/etc/ssh/sshd_config":

ClientAliveInterval 200'
  impact 0.3
  tag check_id: 'C-60070r885964_chk'
  tag severity: 'low'
  tag gid: 'V-256395'
  tag rid: 'SV-256395r885966_rule'
  tag stig_id: 'ESXI-70-000027'
  tag gtitle: 'SRG-OS-000480-VMM-002000'
  tag fix_id: 'F-60013r885965_fix'
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']

  describe 'This check is a manual or policy based check' do
    skip 'This must be reviewed manually'
  end
end
