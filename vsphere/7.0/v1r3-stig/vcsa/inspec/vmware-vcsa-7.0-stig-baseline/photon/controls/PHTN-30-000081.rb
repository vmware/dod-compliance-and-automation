control 'PHTN-30-000081' do
  title 'The Photon operating system must configure sshd to perform strict mode checking of home directory configuration files.'
  desc 'If other users have access to modify user-specific Secure Shell (SSH) configuration files, they may be able to log on to the system as another user.'
  desc 'check', 'At the command line, run the following command:

# sshd -T|&grep -i StrictModes

Expected result:

StrictModes yes

If the output does not match the expected result, this is a finding.'
  desc 'fix', 'Navigate to and open:

/etc/ssh/sshd_config

Ensure the "StrictModes" line is uncommented and set to the following:

StrictModes yes

At the command line, run the following command:

# systemctl restart sshd.service'
  impact 0.5
  tag check_id: 'C-60225r887322_chk'
  tag severity: 'medium'
  tag gid: 'V-256550'
  tag rid: 'SV-256550r887324_rule'
  tag stig_id: 'PHTN-30-000081'
  tag gtitle: 'SRG-OS-000480-GPOS-00227'
  tag fix_id: 'F-60168r887323_fix'
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']

  sshdcommand = input('sshdcommand')
  describe command("#{sshdcommand}|&grep -i StrictModes") do
    its('stdout.strip') { should cmp 'StrictModes yes' }
  end
end
