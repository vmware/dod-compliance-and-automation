control 'PHTN-30-000037' do
  title 'The Photon operating system must configure sshd to disconnect idle Secure Shell (SSH) sessions.'
  desc 'Terminating an idle session within a short time period reduces the window of opportunity for unauthorized personnel to take control of a management session enabled on a console or console port that has been left unattended.'
  desc 'check', 'At the command line, run the following command:

# sshd -T|&grep -i ClientAliveInterval

Expected result:

ClientAliveInterval 900

If the output does not match the expected result, this is a finding.'
  desc 'fix', 'Navigate to and open:

/etc/ssh/sshd_config

Ensure the "ClientAliveInterval" line is uncommented and set to the following:

ClientAliveInterval 900

At the command line, run the following command:

# systemctl restart sshd.service'
  impact 0.5
  tag check_id: 'C-60188r887211_chk'
  tag severity: 'medium'
  tag gid: 'V-256513'
  tag rid: 'SV-256513r887213_rule'
  tag stig_id: 'PHTN-30-000037'
  tag gtitle: 'SRG-OS-000163-GPOS-00072'
  tag fix_id: 'F-60131r887212_fix'
  tag cci: ['CCI-001133']
  tag nist: ['SC-10']

  sshdcommand = input('sshdcommand')
  describe command("#{sshdcommand}|&grep -i ClientAliveInterval") do
    its('stdout.strip') { should cmp 'ClientAliveInterval 900' }
  end
end
