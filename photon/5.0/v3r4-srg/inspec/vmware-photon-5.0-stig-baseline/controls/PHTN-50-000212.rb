control 'PHTN-50-000212' do
  title 'The Photon operating system must configure Secure Shell (SSH) to disable X11 forwarding.'
  desc  'X11 is an older, insecure graphics forwarding protocol. It is not used by Photon and should be disabled as a general best practice to limit attack surface area and communication channels.'
  desc  'rationale', ''
  desc  'check', "
    At the command line, run the following command to verify the running configuration of sshd:

    # sshd -T|&grep -i X11Forwarding

    Example result:

    x11forwarding no

    If \"X11Forwarding\" is not set to \"no\", this is a finding.
  "
  desc 'fix', "
    Navigate to and open:

    /etc/ssh/sshd_config

    Ensure the \"X11Forwarding\" line is uncommented and set to the following:

    X11Forwarding no

    At the command line, run the following command:

    # systemctl restart sshd.service
  "
  impact 0.5
  tag severity: 'medium'
  tag gtitle: 'SRG-OS-000480-GPOS-00227'
  tag gid: 'V-PHTN-50-000212'
  tag rid: 'SV-PHTN-50-000212'
  tag stig_id: 'PHTN-50-000212'
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']

  sshdcommand = input('sshdcommand')
  describe command("#{sshdcommand}|&grep -i X11Forwarding") do
    its('stdout.strip') { should cmp 'X11Forwarding no' }
  end
end
