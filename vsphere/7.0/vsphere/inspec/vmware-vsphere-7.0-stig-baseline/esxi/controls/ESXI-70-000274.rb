control 'ESXI-70-000274' do
  title 'The ESXi host SSH daemon must be configured to only use FIPS 140-2 validated ciphers.'
  desc 'Use of weak or untested encryption algorithms undermines the purposes of using encryption to protect data. ESXi must implement cryptographic modules adhering to the higher standards approved by the federal government because this provides assurance they have been tested and validated.'
  desc 'check', 'From an ESXi shell, run the following command:

# /usr/lib/vmware/openssh/bin/sshd -T|grep ciphers

Expected result:

ciphers aes256-gcm@openssh.com,aes128-gcm@openssh.com,aes256-ctr,aes192-ctr,aes128-ctr

If the output does not match the expected result, this is a finding.'
  desc 'fix', 'From an ESXi shell, add or correct the following line in "/etc/ssh/sshd_config":

Ciphers aes256-gcm@openssh.com,aes128-gcm@openssh.com,aes256-ctr,aes192-ctr,aes128-ctr'
  impact 0.5
  tag check_id: 'C-60124r886126_chk'
  tag severity: 'medium'
  tag gid: 'V-256449'
  tag rid: 'SV-256449r886128_rule'
  tag stig_id: 'ESXI-70-000274'
  tag gtitle: 'SRG-OS-000478-VMM-001980'
  tag fix_id: 'F-60067r886127_fix'
  tag cci: ['CCI-002450']
  tag nist: ['SC-13 b']

  describe 'This check is a manual or policy based check' do
    skip 'This must be reviewed manually'
  end
end
