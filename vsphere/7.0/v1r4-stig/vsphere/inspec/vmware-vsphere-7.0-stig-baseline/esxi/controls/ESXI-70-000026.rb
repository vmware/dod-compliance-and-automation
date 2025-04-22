control 'ESXI-70-000026' do
  title 'The ESXi host Secure Shell (SSH) daemon must set a timeout count on idle sessions.'
  desc 'Setting a timeout ensures that a user login will be terminated as soon as the "ClientAliveCountMax" is reached.'
  desc 'check', 'From an ESXi shell, run the following command:

# /usr/lib/vmware/openssh/bin/sshd -T|grep clientalivecountmax

Expected result:

clientalivecountmax 3

If the output does not match the expected result, this is a finding.'
  desc 'fix', 'From an ESXi shell, add or correct the following line in "/etc/ssh/sshd_config":

ClientAliveCountMax 3'
  impact 0.3
  tag check_id: 'C-60069r885961_chk'
  tag severity: 'low'
  tag gid: 'V-256394'
  tag rid: 'SV-256394r885963_rule'
  tag stig_id: 'ESXI-70-000026'
  tag gtitle: 'SRG-OS-000480-VMM-002000'
  tag fix_id: 'F-60012r885962_fix'
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']

  describe 'This check is a manual or policy based check' do
    skip 'This must be reviewed manually'
  end
end
