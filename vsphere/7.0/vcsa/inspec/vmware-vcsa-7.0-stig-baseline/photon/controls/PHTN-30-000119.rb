control 'PHTN-30-000119' do
  title 'The Photon operating system must configure sshd to restrict AllowTcpForwarding.'
  desc 'While enabling Transmission Control Protocol (TCP) tunnels is a valuable function of sshd, this feature is not appropriate for use on single-purpose appliances.'
  desc 'check', 'At the command line, run the following command:

# sshd -T|&grep -i AllowTcpForwarding

Expected result:

allowtcpforwarding no

If the output does not match the expected result, this is a finding.'
  desc 'fix', 'Navigate to and open:

/etc/ssh/sshd_config

Ensure the "AllowTcpForwarding" line is uncommented and set to the following:

AllowTcpForwarding no

At the command line, run the following command:

# systemctl restart sshd.service'
  impact 0.5
  tag check_id: 'C-60262r887433_chk'
  tag severity: 'medium'
  tag gid: 'V-256587'
  tag rid: 'SV-256587r887435_rule'
  tag stig_id: 'PHTN-30-000119'
  tag gtitle: 'SRG-OS-000480-GPOS-00227'
  tag fix_id: 'F-60205r887434_fix'
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']

  sshdcommand = input('sshdcommand')
  describe command("#{sshdcommand}|&grep -i allowtcpforwarding") do
    its('stdout.strip') { should cmp 'allowtcpforwarding no' }
  end
end
