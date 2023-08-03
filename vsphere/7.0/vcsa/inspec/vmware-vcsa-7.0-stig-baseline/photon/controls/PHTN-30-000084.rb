control 'PHTN-30-000084' do
  title 'The Photon operating system must configure sshd to disallow compression of the encrypted session stream.'
  desc 'If compression is allowed in a Secure Shell (SSH) connection prior to authentication, vulnerabilities in the compression software could result in compromise of the system from an unauthenticated connection.'
  desc 'check', 'At the command line, run the following command:

# sshd -T|&grep -i Compression

Expected result:

Compression no

If the output does not match the expected result, this is a finding.'
  desc 'fix', 'Navigate to and open:

/etc/ssh/sshd_config

Ensure the "Compression" line is uncommented and set to the following:

Compression no

At the command line, run the following command:

# systemctl restart sshd.service'
  impact 0.5
  tag check_id: 'C-60228r887331_chk'
  tag severity: 'medium'
  tag gid: 'V-256553'
  tag rid: 'SV-256553r887333_rule'
  tag stig_id: 'PHTN-30-000084'
  tag gtitle: 'SRG-OS-000480-GPOS-00227'
  tag fix_id: 'F-60171r887332_fix'
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']

  sshdcommand = input('sshdcommand')
  describe command("#{sshdcommand}|&grep -i Compression") do
    its('stdout.strip') { should cmp 'Compression no' }
  end
end
