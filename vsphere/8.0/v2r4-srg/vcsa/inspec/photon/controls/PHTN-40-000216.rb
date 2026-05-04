control 'PHTN-40-000216' do
  title 'The Photon operating system must configure Secure Shell (SSH) to display the last login immediately after authentication.'
  desc 'Providing users with feedback on the last time they logged on via SSH facilitates user recognition and reporting of unauthorized account use.'
  desc 'check', 'At the command line, run the following command to verify the running configuration of sshd:

# sshd -T|&grep -i PrintLastLog

Example result:

printlastlog yes

If "PrintLastLog" is not set to "yes", this is a finding.'
  desc 'fix', 'Navigate to and open:

/etc/ssh/sshd_config

Ensure the "PrintLastLog" line is uncommented and set to the following:

PrintLastLog yes

At the command line, run the following command:

# systemctl restart sshd.service'
  impact 0.5
  tag check_id: 'C-62619r933696_chk'
  tag severity: 'medium'
  tag gid: 'V-258879'
  tag rid: 'SV-258879r991589_rule'
  tag stig_id: 'PHTN-40-000216'
  tag gtitle: 'SRG-OS-000480-GPOS-00227'
  tag fix_id: 'F-62528r933697_fix'
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']

  sshdcommand = input('sshdcommand')
  describe command("#{sshdcommand}|&grep -i PrintLastLog") do
    its('stdout.strip') { should cmp 'PrintLastLog yes' }
  end
end
