control 'ESXI-80-000187' do
  title 'The ESXi host Secure Shell (SSH) daemon must be configured to only use FIPS 140-2 validated ciphers.'
  desc  'Use of weak or untested encryption algorithms undermines the purposes of utilizing encryption to protect data. ESXi must implement cryptographic modules adhering to the higher standards approved by the federal government since this provides assurance they have been tested and validated.'
  desc  'rationale', ''
  desc  'check', "
    From an ESXi shell, run the following command:

    # /usr/lib/vmware/openssh/bin/sshd -T | grep ciphers

    Expected result:

    ciphers aes256-gcm@openssh.com,aes128-gcm@openssh.com,aes256-ctr,aes192-ctr,aes128-ctr

    If the output does not match the expected result, this is a finding.
  "
  desc 'fix', "
    From an ESXi shell, add or update the following line in \"/etc/ssh/sshd_config\":

    Ciphers aes256-gcm@openssh.com,aes128-gcm@openssh.com,aes256-ctr,aes192-ctr,aes128-ctr

    Note: The ciphers line must be after the FipsMode setting.
  "
  impact 0.5
  tag severity: 'medium'
  tag gtitle: 'SRG-OS-000478-VMM-001980'
  tag gid: 'V-ESXI-80-000187'
  tag rid: 'SV-ESXI-80-000187'
  tag stig_id: 'ESXI-80-000187'
  tag cci: ['CCI-002450']
  tag nist: ['SC-13']

  describe 'This check is a manual or policy based check and must be reviewed manually.' do
    skip 'This check is a manual or policy based check and must be reviewed manually.'
  end
end
