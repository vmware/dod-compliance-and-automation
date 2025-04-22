control 'PHTN-30-000079' do
  title 'The Photon operating system must configure sshd to disable environment processing.'
  desc 'Enabling environment processing may enable users to bypass access restrictions in some configurations and must therefore be disabled.'
  desc 'check', 'At the command line, run the following command:

sshd -T|&grep -i PermitUserEnvironment

Expected result:

PermitUserEnvironment no

If the output does not match the expected result, this is a finding.'
  desc 'fix', 'Navigate to and open:

/etc/ssh/sshd_config

Ensure the "PermitUserEnvironment" line is uncommented and set to the following:

PermitUserEnvironment no

At the command line, run the following command:

# systemctl restart sshd.service'
  impact 0.5
  tag check_id: 'C-60223r887316_chk'
  tag severity: 'medium'
  tag gid: 'V-256548'
  tag rid: 'SV-256548r887318_rule'
  tag stig_id: 'PHTN-30-000079'
  tag gtitle: 'SRG-OS-000480-GPOS-00227'
  tag fix_id: 'F-60166r887317_fix'
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']

  sshdcommand = input('sshdcommand')
  describe command("#{sshdcommand}|&grep -i PermitUserEnvironment") do
    its('stdout.strip') { should cmp 'PermitUserEnvironment no' }
  end
end
