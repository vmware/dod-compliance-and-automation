control 'PHTN-40-000202' do
  title 'The Photon operating system must prohibit password reuse for a minimum of five generations by using a password history file.'
  desc  'Password complexity, or strength, is a measure of the effectiveness of a password in resisting attempts at guessing and brute-force attacks. If the information system or application allows the user to consecutively reuse their password when that password has exceeded its defined lifetime, the end result is a password that is not changed as per policy requirements.'
  desc  'rationale', ''
  desc  'check', "
    At the command line, run the following command to verify a password history file exists and is protected from unauthorized access:

    # ls -al /etc/security/opasswd

    If \"/etc/security/opasswd\" does not exist, this is a finding.
    If \"/etc/security/opasswd\" is not owned by root or group owned by root or has permissions other than \"0600\", this is a finding.
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
  tag gid: 'V-PHTN-40-000202'
  tag rid: 'SV-PHTN-40-000202'
  tag stig_id: 'PHTN-40-000202'
  tag cci: ['CCI-000200']
  tag nist: ['IA-5 (1) (e)']

  describe file('/etc/security/opasswd') do
    it { should exist }
    its('owner') { should cmp 'root' }
    its('group') { should cmp 'root' }
    its('mode') { should cmp '0600' }
  end
end
