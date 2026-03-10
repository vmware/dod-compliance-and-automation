control 'PHTN-50-000207' do
  title 'The Photon operating system must configure Secure Shell (SSH) to disallow authentication with an empty password.'
  desc  'Blank passwords are one of the first things an attacker checks for when probing a system. Even if the user somehow has a blank password on the OS, SSH must not allow that user to log in.'
  desc  'rationale', ''
  desc  'check', "
    At the command line, run the following command to verify the running configuration of sshd:

    # sshd -T|&grep -i PermitEmptyPasswords

    Example result:

    permitemptypasswords no

    If \"PermitEmptyPasswords\" is not set to \"no\", this is a finding.
  "
  desc 'fix', "
    Navigate to and open:

    /etc/ssh/sshd_config

    Ensure the \"PermitEmptyPasswords\" line is uncommented and set to the following:

    PermitEmptyPasswords no

    At the command line, run the following command:

    # systemctl restart sshd.service
  "
  impact 0.7
  tag severity: 'high'
  tag gtitle: 'SRG-OS-000480-GPOS-00229'
  tag gid: 'V-PHTN-50-000207'
  tag rid: 'SV-PHTN-50-000207'
  tag stig_id: 'PHTN-50-000207'
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']

  sshdcommand = input('sshdcommand')
  describe command("#{sshdcommand}|&grep -i PermitEmptyPasswords") do
    its('stdout.strip') { should cmp 'PermitEmptyPasswords no' }
  end
end
