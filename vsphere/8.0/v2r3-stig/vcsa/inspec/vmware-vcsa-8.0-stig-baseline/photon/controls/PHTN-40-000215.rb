control 'PHTN-40-000215' do
  title 'The Photon operating system must configure Secure Shell (SSH) to disallow compression of the encrypted session stream.'
  desc 'If compression is allowed in an SSH connection prior to authentication, vulnerabilities in the compression software could result in compromise of the system from an unauthenticated connection.'
  desc 'check', 'At the command line, run the following command to verify the running configuration of sshd:

# sshd -T|&grep -i Compression

Example result:

compression no

If there is no output or if "Compression" is not set to "delayed" or "no", this is a finding.'
  desc 'fix', 'Navigate to and open:

/etc/ssh/sshd_config

Ensure the "Compression" line is uncommented and set to the following:

Compression no

At the command line, run the following command:

# systemctl restart sshd.service'
  impact 0.5
  tag check_id: 'C-62618r933693_chk'
  tag severity: 'medium'
  tag gid: 'V-258878'
  tag rid: 'SV-258878r991589_rule'
  tag stig_id: 'PHTN-40-000215'
  tag gtitle: 'SRG-OS-000480-GPOS-00227'
  tag fix_id: 'F-62527r933694_fix'
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']

  sshdcommand = input('sshdcommand')
  describe command("#{sshdcommand}|&grep -i Compression") do
    its('stdout.strip') { should cmp 'Compression no' }
  end
end
