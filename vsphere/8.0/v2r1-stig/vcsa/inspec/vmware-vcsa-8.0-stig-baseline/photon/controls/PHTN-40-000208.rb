control 'PHTN-40-000208' do
  title 'The Photon operating system must configure Secure Shell (SSH) to disable user environment processing.'
  desc 'Enabling user environment processing may enable users to bypass access restrictions in some configurations and must therefore be disabled.'
  desc 'check', 'At the command line, run the following command to verify the running configuration of sshd:

# sshd -T|&grep -i PermitUserEnvironment

Example result:

permituserenvironment no

If "PermitUserEnvironment" is not set to "no", this is a finding.'
  desc 'fix', 'Navigate to and open:

/etc/ssh/sshd_config

Ensure the "PermitUserEnvironment" line is uncommented and set to the following:

PermitUserEnvironment no

At the command line, run the following command:

# systemctl restart sshd.service'
  impact 0.7
  tag check_id: 'C-62611r933672_chk'
  tag severity: 'high'
  tag gid: 'V-258871'
  tag rid: 'SV-258871r991591_rule'
  tag stig_id: 'PHTN-40-000208'
  tag gtitle: 'SRG-OS-000480-GPOS-00229'
  tag fix_id: 'F-62520r933673_fix'
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']

  sshdcommand = input('sshdcommand')
  describe command("#{sshdcommand}|&grep -i PermitUserEnvironment") do
    its('stdout.strip') { should cmp 'PermitUserEnvironment no' }
  end
end
