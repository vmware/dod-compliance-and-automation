control 'ESXI-80-000211' do
  title 'The ESXi host Secure Shell (SSH) daemon must set a timeout interval on idle sessions.'
  desc  'Automatically logging out idle users guards against compromises via hijacked administrative sessions.'
  desc  'rationale', ''
  desc  'check', "
    From an ESXi shell, run the following command:

    # /usr/lib/vmware/openssh/bin/sshd -T | grep clientaliveinterval

    Expected result:

    clientaliveinterval 200

    If the output does not match the expected result, this is a finding.
  "
  desc 'fix', "
    From an ESXi shell, add or update the following line in \"/etc/ssh/sshd_config\":

    ClientAliveInterval 200
  "
  impact 0.3
  tag severity: 'low'
  tag gtitle: 'SRG-OS-000480-VMM-002000'
  tag gid: 'V-ESXI-80-000211'
  tag rid: 'SV-ESXI-80-000211'
  tag stig_id: 'ESXI-80-000211'
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']

  describe 'This check is a manual or policy based check and must be reviewed manually.' do
    skip 'This check is a manual or policy based check and must be reviewed manually.'
  end
end
