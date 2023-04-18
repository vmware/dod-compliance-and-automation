control 'ESXI-80-000210' do
  title 'The ESXi host Secure Shell (SSH) daemon must set a timeout count on idle sessions.'
  desc  'Setting a timeout ensures that a user login will be terminated as soon as the "ClientAliveCountMax" is reached.'
  desc  'rationale', ''
  desc  'check', "
    From an ESXi shell, run the following command:

    # /usr/lib/vmware/openssh/bin/sshd -T | grep clientalivecountmax

    Expected result:

    clientalivecountmax 3

    If the output does not match the expected result, this is a finding.
  "
  desc 'fix', "
    From an ESXi shell, add or update the following line in \"/etc/ssh/sshd_config\":

    ClientAliveCountMax 3
  "
  impact 0.3
  tag severity: 'low'
  tag gtitle: 'SRG-OS-000480-VMM-002000'
  tag gid: 'V-ESXI-80-000210'
  tag rid: 'SV-ESXI-80-000210'
  tag stig_id: 'ESXI-80-000210'
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']

  describe 'This check is a manual or policy based check and must be reviewed manually.' do
    skip 'This check is a manual or policy based check and must be reviewed manually.'
  end
end
