control 'PHTN-50-000213' do
  title 'The Photon operating system must configure Secure Shell (SSH) to perform strict mode checking of home directory configuration files.'
  desc  'If other users have access to modify user-specific SSH configuration files, they may be able to log on to the system as another user.'
  desc  'rationale', ''
  desc  'check', "
    At the command line, run the following command to verify the running configuration of sshd:

    # sshd -T|&grep -i StrictModes

    Example result:

    strictmodes yes

    If \"StrictModes\" is not set to \"yes\", this is a finding.
  "
  desc 'fix', "
    Navigate to and open:

    /etc/ssh/sshd_config

    Ensure the \"StrictModes\" line is uncommented and set to the following:

    StrictModes yes

    At the command line, run the following command:

    # systemctl restart sshd.service
  "
  impact 0.5
  tag severity: 'medium'
  tag gtitle: 'SRG-OS-000480-GPOS-00227'
  tag gid: 'V-PHTN-50-000213'
  tag rid: 'SV-PHTN-50-000213'
  tag stig_id: 'PHTN-50-000213'
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']

  sshdcommand = input('sshdcommand')
  describe command("#{sshdcommand}|&grep -i StrictModes") do
    its('stdout.strip') { should cmp 'StrictModes yes' }
  end
end
