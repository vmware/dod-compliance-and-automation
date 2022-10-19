control 'PHTN-30-000118' do
  title 'The Photon operating system must ensure that the old passwords are being stored.'
  desc  'Password complexity, or strength, is a measure of the effectiveness of a password in resisting attempts at guessing and brute-force attacks. If the information system or application allows the user to consecutively reuse their password when that password has exceeded its defined lifetime, the end result is a password that is not changed as per policy requirements.'
  desc  'rationale', ''
  desc  'check', "
    At the command line, execute the following command:

    # ls -al /etc/security/opasswd

    If /etc/security/opasswd does not exist, this is a finding.
  "
  desc 'fix', "
    At the command line, execute the following command(s):

    # touch /etc/security/opasswd
    # chown root:root /etc/security/opasswd
    # chmod 0600 /etc/security/opasswd
  "
  impact 0.5
  tag severity: 'medium'
  tag gtitle: 'SRG-OS-000077-GPOS-00045'
  tag gid: nil
  tag rid: nil
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
