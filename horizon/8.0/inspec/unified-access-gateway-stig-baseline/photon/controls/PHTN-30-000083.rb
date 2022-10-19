control 'PHTN-30-000083' do
  title 'The Photon operating system must configure sshd to disallow authentication with an empty password.'
  desc  'Blank passwords are one of the first things an attacker checks for when probing a system. Even is the user somehow has a blank password on the OS, sshd must not allow that user to log in.'
  desc  'rationale', ''
  desc  'check', "
    At the command line, execute the following command:

    # sshd -T|&grep -i PermitEmptyPasswords

    Expected result:

    PermitEmptyPasswords no

    If the output does not match the expected result, this is a finding.
  "
  desc 'fix', "
    Navigate to and open:

    /etc/ssh/sshd_config

    Ensure that the \"PermitEmptyPasswords\" line is uncommented and set to the following:

    PermitEmptyPasswords no

    At the command line, execute the following command:

    # systemctl restart sshd.service
  "
  impact 0.5
  tag severity: 'medium'
  tag gtitle: 'SRG-OS-000480-GPOS-00227'
  tag gid: nil
  tag rid: nil
  tag stig_id: 'PHTN-30-000083'
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']

  sshdcommand = input('sshdcommand')
  describe command("#{sshdcommand}|&grep -i PermitEmptyPasswords") do
    its('stdout.strip') { should cmp 'PermitEmptyPasswords no' }
  end
end
