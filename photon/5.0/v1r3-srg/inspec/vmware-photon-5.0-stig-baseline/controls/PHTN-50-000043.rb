control 'PHTN-50-000043' do
  title 'The Photon operating system must prohibit password reuse for a minimum of five generations.'
  desc  'Password complexity, or strength, is a measure of the effectiveness of a password in resisting attempts at guessing and brute-force attacks. If the information system or application allows the user to consecutively reuse their password when that password has exceeded its defined lifetime, the end result is a password that is not changed as per policy requirements.'
  desc  'rationale', ''
  desc  'check', "
    At the command line, run the following commands to verify passwords are not reused for a minimum of five generations:

    # grep '^remember' /etc/security/pwhistory.conf

    Example result:

    remember = 5

    If the \"remember\" option is not set to \"5\" or greater, this is a finding.

    Note: If pwhistory.conf is not used to configure pam_pwhistory.so, these options may be specified on the pwhistory lines in the system-password file.
  "
  desc 'fix', "
    Navigate to and open:

    /etc/security/pwhistory.conf

    Add or update the following lines:

    remember = 5
  "
  impact 0.5
  tag severity: 'medium'
  tag gtitle: 'SRG-OS-000077-GPOS-00045'
  tag gid: 'V-PHTN-50-000043'
  tag rid: 'SV-PHTN-50-000043'
  tag stig_id: 'PHTN-50-000043'
  tag cci: ['CCI-000200']
  tag nist: ['IA-5 (1) (e)']

  if input('useHistoryConf')
    describe parse_config_file('/etc/security/pwhistory.conf') do
      its('remember') { should cmp >= 5 }
    end
  else
    describe file('/etc/pam.d/system-password') do
      its('content') { should match /^password\s+(required|requisite)\s+pam_pwhistory\.so\s+(?=.*\bremember=5\b).*$/ }
    end
  end
end
