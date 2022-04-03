control 'PHTN-67-000086' do
  title "The Photon operating system must configure sshd to perform strict mode
checking of home directory configuration files."
  desc  "If other users have access to modify user-specific SSH configuration
files, they may be able to log on to the system as another user."
  desc  'rationale', ''
  desc  'check', "
    At the command line, execute the following command:

    # sshd -T|&grep -i StrictModes

    Expected result:

    StrictModes yes

    If the output does not match the expected result, this is a finding.
  "
  desc 'fix', "
    Open /etc/ssh/sshd_config with a text editor.

    Ensure that the \"StrictModes\" line is uncommented and set to the
following:

    StrictModes yes

    At the command line, execute the following command:

    # service sshd reload
  "
  impact 0.5
  tag severity: 'medium'
  tag gtitle: 'SRG-OS-000480-GPOS-00227'
  tag gid: 'V-239157'
  tag rid: 'SV-239157r675279_rule'
  tag stig_id: 'PHTN-67-000086'
  tag fix_id: 'F-42327r675278_fix'
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']

  describe command('sshd -T|&grep -i StrictModes') do
    its('stdout.strip') { should cmp 'StrictModes yes' }
  end
end
