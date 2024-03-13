control 'PHTN-30-000038' do
  title 'The Photon operating system must configure sshd to disconnect idle Secure Shell (SSH) sessions.'
  desc 'Terminating an idle session within a short time period reduces the window of opportunity for unauthorized personnel to take control of a management session enabled on a console or console port that has been left unattended.'
  desc 'check', 'At the command line, run the following command:

# sshd -T|&grep -i ClientAliveCountMax

Expected result:

ClientAliveCountMax 0

If the output does not match the expected result, this is a finding.'
  desc 'fix', 'Navigate to and open:

/etc/ssh/sshd_config

Ensure the "ClientAliveCountMax" line is uncommented and set to the following:

ClientAliveCountMax 0

At the command line, run the following command:

# systemctl restart sshd.service'
  impact 0.5
  tag check_id: 'C-60189r887214_chk'
  tag severity: 'medium'
  tag gid: 'V-256514'
  tag rid: 'SV-256514r887216_rule'
  tag stig_id: 'PHTN-30-000038'
  tag gtitle: 'SRG-OS-000163-GPOS-00072'
  tag fix_id: 'F-60132r887215_fix'
  tag cci: ['CCI-001133']
  tag nist: ['SC-10']

  sshdcommand = input('sshdcommand')
  describe command("#{sshdcommand}|&grep -i ClientAliveCountMax") do
    its('stdout.strip') { should cmp 'ClientAliveCountMax 0' }
  end
end
