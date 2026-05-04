control 'PHTN-40-000217' do
  title 'The Photon operating system must configure Secure Shell (SSH) to ignore user-specific trusted hosts lists.'
  desc 'SSH trust relationships enable trivial lateral spread after a host compromise and therefore must be explicitly disabled. Individual users can have a local list of trusted remote machines, which must also be ignored while disabling host-based authentication generally.'
  desc 'check', 'At the command line, run the following command to verify the running configuration of sshd:

# sshd -T|&grep -i IgnoreRhosts

Example result:

ignorerhosts yes

If "IgnoreRhosts" is not set to "yes", this is a finding.'
  desc 'fix', 'Navigate to and open:

/etc/ssh/sshd_config

Ensure the "IgnoreRhosts" line is uncommented and set to the following:

IgnoreRhosts yes

At the command line, run the following command:

# systemctl restart sshd.service'
  impact 0.5
  tag check_id: 'C-62620r933699_chk'
  tag severity: 'medium'
  tag gid: 'V-258880'
  tag rid: 'SV-258880r991589_rule'
  tag stig_id: 'PHTN-40-000217'
  tag gtitle: 'SRG-OS-000480-GPOS-00227'
  tag fix_id: 'F-62529r933700_fix'
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']

  sshdcommand = input('sshdcommand')
  describe command("#{sshdcommand}|&grep -i IgnoreRhosts") do
    its('stdout.strip') { should cmp 'IgnoreRhosts yes' }
  end
end
