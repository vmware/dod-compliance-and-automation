control 'PHTN-50-000219' do
  title 'The Photon operating system must configure Secure Shell (SSH) to limit the number of allowed login attempts per connection.'
  desc  'By setting the login attempt limit to a low value, an attacker will be forced to reconnect frequently, which severely limits the speed and effectiveness of brute-force attacks.'
  desc  'rationale', ''
  desc  'check', "
    At the command line, run the following command to verify the running configuration of sshd:

    # sshd -T|&grep -i MaxAuthTries

    Example result:

    maxauthtries 6

    If \"MaxAuthTries\" is not set to \"6\", this is a finding.
  "
  desc 'fix', "
    Navigate to and open:

    /etc/ssh/sshd_config

    Ensure the \"MaxAuthTries\" line is uncommented and set to the following:

    MaxAuthTries 6

    At the command line, run the following command:

    # systemctl restart sshd.service
  "
  impact 0.5
  tag severity: 'medium'
  tag gtitle: 'SRG-OS-000480-GPOS-00227'
  tag gid: 'V-PHTN-50-000219'
  tag rid: 'SV-PHTN-50-000219'
  tag stig_id: 'PHTN-50-000219'
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']

  sshdcommand = input('sshdcommand')
  describe command("#{sshdcommand}|&grep -i MaxAuthTries") do
    its('stdout.strip') { should cmp 'MaxAuthTries 6' }
  end
end
