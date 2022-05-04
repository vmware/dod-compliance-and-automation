control 'ESXI-70-000027' do
  title 'The ESXi host SSH daemon must set a timeout interval on idle sessions.'
  desc  'Automatically logging out idle users guards against compromises via hijacked administrative sessions.'
  desc  'rationale', ''
  desc  'check', "
    From an ESXi shell, run the following command(s):

    # /usr/lib/vmware/openssh/bin/sshd -T|grep clientaliveinterval

    Expected result:

    clientaliveinterval 200

    If the output does not match the expected result, this is a finding.
  "
  desc 'fix', "
    From an ESXi shell, add or correct the following line in \"/etc/ssh/sshd_config\":

    ClientAliveInterval 200
  "
  impact 0.7
  tag severity: 'high'
  tag gtitle: 'SRG-OS-000480-VMM-002000'
  tag gid: nil
  tag rid: nil
  tag stig_id: 'ESXI-70-000027'
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']

  describe 'This check is a manual or policy based check' do
    skip 'This must be reviewed manually'
  end
end
