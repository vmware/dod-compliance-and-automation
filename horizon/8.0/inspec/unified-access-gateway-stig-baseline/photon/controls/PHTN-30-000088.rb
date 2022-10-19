control 'PHTN-30-000088' do
  title 'The Photon operating system must configure sshd to limit the number of allowed login attempts per connection.'
  desc  'By setting the login attempt limit to a low value, an attacker will be forced to reconnect frequently, which severely limits the speed and effectiveness of brute-force attacks.'
  desc  'rationale', ''
  desc  'check', "
    At the command line, execute the following command:

    # sshd -T|&grep -i MaxAuthTries

    Expected result:

    MaxAuthTries 6

    If the output is set to a higher value than expected, or does not match the expected result, this is a finding.
  "
  desc 'fix', "
    Navigate to and open:

    /etc/ssh/sshd_config

    Ensure that the \"MaxAuthTries\" line is uncommented and set to the following:

    MaxAuthTries 6

    At the command line, execute the following command:

    # systemctl restart sshd.service
  "
  impact 0.5
  tag severity: 'medium'
  tag gtitle: 'SRG-OS-000480-GPOS-00227'
  tag gid: nil
  tag rid: nil
  tag stig_id: 'PHTN-30-000088'
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']

  sshdcommand = input('sshdcommand')

  describe command("#{sshdcommand}|&grep -i MaxAuthTries | cut -d ' ' -f 2") do
    its('stdout.strip') { should cmp <= 6 }
  end
end
