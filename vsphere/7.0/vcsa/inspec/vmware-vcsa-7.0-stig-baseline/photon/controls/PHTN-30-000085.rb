control 'PHTN-30-000085' do
  title 'The Photon operating system must configure sshd to display the last login immediately after authentication.'
  desc 'Providing users with feedback on the last time they logged on via Secure Shell (SSH) facilitates user recognition and reporting of unauthorized account use.'
  desc 'check', 'At the command line, run the following command:

# sshd -T|&grep -i PrintLastLog

Expected result:

PrintLastLog yes

If the output does not match the expected result, this is a finding.'
  desc 'fix', 'Navigate to and open:

/etc/ssh/sshd_config

Ensure the "PrintLastLog" line is uncommented and set to the following:

PrintLastLog yes

At the command line, run the following command:

# systemctl restart sshd.service'
  impact 0.5
  tag check_id: 'C-60229r887334_chk'
  tag severity: 'medium'
  tag gid: 'V-256554'
  tag rid: 'SV-256554r887336_rule'
  tag stig_id: 'PHTN-30-000085'
  tag gtitle: 'SRG-OS-000480-GPOS-00227'
  tag fix_id: 'F-60172r887335_fix'
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']

  sshdcommand = input('sshdcommand')
  describe command("#{sshdcommand}|&grep -i PrintLastLog") do
    its('stdout.strip') { should cmp 'PrintLastLog yes' }
  end
end
