control 'PHTN-67-000094' do
  title "The Photon operating system must configure sshd to limit the number of
allowed login attempts per connection."
  desc  "By setting the login attempt limit to a low value, an attacker will be
forced to reconnect frequently, which severely limits the speed and
effectiveness of brute-force attacks."
  desc  'rationale', ''
  desc  'check', "
    At the command line, execute the following command:

    # sshd -T|&grep -i MaxAuthTries

    Expected result:

    MaxAuthTries 2

    If the output does not match the expected result, this is a finding.
  "
  desc 'fix', "
    Open /etc/ssh/sshd_config with a text editor.

    Ensure that the \"MaxAuthTries\" line is uncommented and set to the
following:

    MaxAuthTries 2

    At the command line, execute the following command:

    # service sshd reload
  "
  impact 0.5
  tag severity: 'medium'
  tag gtitle: 'SRG-OS-000480-GPOS-00227'
  tag gid: 'V-239165'
  tag rid: 'SV-239165r675303_rule'
  tag stig_id: 'PHTN-67-000094'
  tag fix_id: 'F-42335r675302_fix'
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']

  describe command('sshd -T|&grep -i MaxAuthTries') do
    its('stdout.strip') { should cmp 'MaxAuthTries 2' }
  end
end
