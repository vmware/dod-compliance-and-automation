control 'PHTN-30-000081' do
  title 'The Photon operating system must configure sshd to perform strict mode checking of home directory configuration files.'
  desc  'If other users have access to modify user-specific SSH configuration files, they may be able to log on to the system as another user.'
  desc  'rationale', ''
  desc  'check', "
    At the command line, execute the following command:

    # sshd -T|&grep -i StrictModes

    Expected result:

    StrictModes yes

    If the output does not match the expected result, this is a finding.
  "
  desc 'fix', "
    Navigate to and open:

    /etc/ssh/sshd_config

    Ensure that the \"StrictModes\" line is uncommented and set to the following:

    StrictModes yes

    At the command line, execute the following command:

    # systemctl restart sshd.service
  "
  impact 0.5
  tag severity: 'medium'
  tag gtitle: 'SRG-OS-000480-GPOS-00227'
  tag gid: nil
  tag rid: nil
  tag stig_id: 'PHTN-30-000081'
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']

  sshdcommand = input('sshdcommand')
  describe command("#{sshdcommand}|&grep -i StrictModes") do
    its('stdout.strip') { should cmp 'StrictModes yes' }
  end
end
