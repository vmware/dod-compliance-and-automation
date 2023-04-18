control 'ESXI-80-000203' do
  title 'The ESXi host Secure Shell (SSH) daemon must not allow authentication using an empty password.'
  desc  'Configuring this setting for the SSH daemon provides additional assurance that remote logon via SSH will require a password, even in the event of misconfiguration elsewhere.'
  desc  'rationale', ''
  desc  'check', "
    From an ESXi shell, run the following command:

    # /usr/lib/vmware/openssh/bin/sshd -T | grep permitemptypasswords

    Expected result:

    permitemptypasswords no

    If the output does not match the expected result, this is a finding.
  "
  desc 'fix', "
    From an ESXi shell, add or update the following line in \"/etc/ssh/sshd_config\":

    PermitEmptyPasswords no
  "
  impact 0.5
  tag severity: 'medium'
  tag gtitle: 'SRG-OS-000480-VMM-002000'
  tag gid: 'V-ESXI-80-000203'
  tag rid: 'SV-ESXI-80-000203'
  tag stig_id: 'ESXI-80-000203'
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']

  describe 'This check is a manual or policy based check and must be reviewed manually.' do
    skip 'This check is a manual or policy based check and must be reviewed manually.'
  end
end
