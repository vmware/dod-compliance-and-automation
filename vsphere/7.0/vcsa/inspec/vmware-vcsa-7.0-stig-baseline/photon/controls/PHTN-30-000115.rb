control 'PHTN-30-000115' do
  title 'The Photon operating system must configure sshd to disallow HostbasedAuthentication.'
  desc 'Secure Shell (SSH) trust relationships enable trivial lateral spread after a host compromise and therefore must be explicitly disabled.'
  desc 'check', 'At the command line, run the following command:

# sshd -T|&grep -i HostbasedAuthentication

Expected result:

hostbasedauthentication no

If the output does not match the expected result, this is a finding.'
  desc 'fix', 'Navigate to and open:

/etc/ssh/sshd_config

Ensure the "HostbasedAuthentication" line is uncommented and set to the following:

HostbasedAuthentication no

At the command line, run the following command:

# systemctl restart sshd.service'
  impact 0.5
  tag check_id: 'C-60259r887424_chk'
  tag severity: 'medium'
  tag gid: 'V-256584'
  tag rid: 'SV-256584r887426_rule'
  tag stig_id: 'PHTN-30-000115'
  tag gtitle: 'SRG-OS-000480-GPOS-00229'
  tag fix_id: 'F-60202r887425_fix'
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']

  sshdcommand = input('sshdcommand')
  describe command("#{sshdcommand}|&grep -i HostbasedAuthentication") do
    its('stdout.strip') { should cmp 'HostbasedAuthentication no' }
  end
end
