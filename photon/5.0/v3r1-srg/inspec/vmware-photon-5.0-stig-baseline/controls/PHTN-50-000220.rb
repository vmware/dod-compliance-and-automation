control 'PHTN-50-000220' do
  title 'The Photon operating system must configure Secure Shell (SSH) to restrict AllowTcpForwarding.'
  desc  'While enabling TCP tunnels is a valuable function of SSH, this feature is not appropriate for use on single purpose appliances.'
  desc  'rationale', ''
  desc  'check', "
    At the command line, run the following command to verify the running configuration of sshd:

    # sshd -T|&grep -i AllowTcpForwarding

    Example result:

    allowtcpforwarding no

    If \"AllowTcpForwarding\" is not set to \"no\", this is a finding.
  "
  desc 'fix', "
    Navigate to and open:

    /etc/ssh/sshd_config

    Ensure the \"AllowTcpForwarding\" line is uncommented and set to the following:

    AllowTcpForwarding no

    At the command line, run the following command:

    # systemctl restart sshd.service
  "
  impact 0.5
  tag severity: 'medium'
  tag gtitle: 'SRG-OS-000480-GPOS-00227'
  tag gid: 'V-PHTN-50-000220'
  tag rid: 'SV-PHTN-50-000220'
  tag stig_id: 'PHTN-50-000220'
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']

  sshdcommand = input('sshdcommand')
  describe command("#{sshdcommand}|&grep -i AllowTcpForwarding") do
    its('stdout.strip') { should cmp 'AllowTcpForwarding no' }
  end
end
