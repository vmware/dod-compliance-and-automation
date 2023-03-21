control 'PHTN-30-000118' do
  title 'The Photon operating system must ensure the old passwords are being stored.'
  desc  'Password complexity, or strength, is a measure of the effectiveness of a password in resisting attempts at guessing and brute-force attacks. If the information system or application allows the user to consecutively reuse their password when that password has exceeded its defined lifetime, the result is a password that is not changed per policy requirements.'
  desc  'rationale', ''
  desc  'check', "
    At the command line, run the following command:

    # ls -al /etc/security/opasswd

    If /etc/security/opasswd does not exist, this is a finding.
  "
  desc 'fix', "
    At the command line, run the following commands:

    # touch /etc/security/opasswd
    # chown root:root /etc/security/opasswd
    # chmod 0600 /etc/security/opasswd
  "
  impact 0.5
  tag severity: 'medium'
  tag gtitle: 'SRG-OS-000077-GPOS-00045'
  tag gid: 'V-256586'
  tag rid: 'SV-256586r887432_rule'
  tag stig_id: 'PHTN-30-000118'
  tag cci: ['CCI-000200']
  tag nist: ['IA-5 (1) (e)']

  describe file('/etc/security/opasswd') do
    it { should exist }
    its('owner') { should cmp 'root' }
    its('group') { should cmp 'root' }
    its('mode') { should cmp '0600' }
  end
end
