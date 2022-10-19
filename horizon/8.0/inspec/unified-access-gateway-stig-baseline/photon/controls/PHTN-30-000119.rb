control 'PHTN-30-000119' do
  title 'The Photon operating system must configure sshd to restrict AllowTcpForwarding.'
  desc  'While enabling TCP tunnels is a valuable function of sshd, this feature is not appropriate for use on single purpose appliances.'
  desc  'rationale', ''
  desc  'check', "
    At the command line, execute the following command:

    # sshd -T|&grep -i AllowTcpForwarding

    Expected result:

    allowtcpforwarding no

    If the output does not match the expected result, this is a finding.
  "
  desc 'fix', "
    Navigate to and open:

    /etc/ssh/sshd_config

    Ensure that the \"AllowTcpForwarding\" line is uncommented and set to the following:

    AllowTcpForwarding no

    At the command line, execute the following command:

    # systemctl restart sshd.service
  "
  impact 0.5
  tag severity: 'medium'
  tag gtitle: 'SRG-OS-000480-GPOS-00227'
  tag gid: nil
  tag rid: nil
  tag stig_id: 'PHTN-30-000119'
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']

  sshdcommand = input('sshdcommand')
  describe command("#{sshdcommand}|&grep -i allowtcpforwarding") do
    its('stdout.strip') { should cmp 'allowtcpforwarding no' }
  end
end
