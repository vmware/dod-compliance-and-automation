control 'PHTN-67-000030' do
  title "The Photon operating system must ensure old passwords are being
stored."
  desc  "Password complexity, or strength, is a measure of the effectiveness of
a password in resisting attempts at guessing and brute-force attacks. If the
information system or application allows the user to consecutively reuse their
password when that password has exceeded its defined lifetime, the end result
is a password that is not changed as per policy requirements."
  desc  'rationale', ''
  desc  'check', "
    At the command line, execute the following command:

    # ls -al /etc/security/opasswd

    If \"/etc/security/opasswd\" does not exist, this is a finding.
  "
  desc 'fix', "
    At the command line, execute the following commands:

    # touch /etc/security/opasswd
    # chown root:root /etc/security/opasswd
    # chmod 0600 /etc/security/opasswd
  "
  impact 0.5
  tag severity: 'medium'
  tag gtitle: 'SRG-OS-000077-GPOS-00045'
  tag gid: 'V-239102'
  tag rid: 'SV-239102r675114_rule'
  tag stig_id: 'PHTN-67-000030'
  tag fix_id: 'F-42272r675113_fix'
  tag cci: ['CCI-000200']
  tag nist: ['IA-5 (1) (e)']

  describe file('/etc/security/opasswd') do
    it { should exist }
  end
end
