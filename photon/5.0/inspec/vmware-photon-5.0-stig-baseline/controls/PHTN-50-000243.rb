control 'PHTN-50-000243' do
  title 'The Photon operating system must be configured to use the pam_pwhistory.so module.'
  desc  'Password complexity, or strength, is a measure of the effectiveness of a password in resisting attempts at guessing and brute-force attacks. If the information system or application allows the user to consecutively reuse their password when that password has exceeded its defined lifetime, the end result is a password that is not changed as per policy requirements.'
  desc  'rationale', ''
  desc  'check', "
    At the command line, run the following command to verify the pam_pwhistory.so module is used:

    # grep '^password' /etc/pam.d/system-password

    Example result:

    password required pam_pwhistory.so use_authtok
    password required pam_pwquality.so use_authtok
    password required pam_unix.so sha512 shadow use_authtok

    If the \"pam_pwhistory.so\" module is not present, this is a finding.
    If \"use_authtok\" is not present for the \"pam_pwhistory.so\" module, this is a finding.
    If \"conf\" or \"file\" are present for the \"pam_pwhistory.so\" module, this is a finding.
  "
  desc 'fix', "
    Navigate to and open:

    /etc/pam.d/system-password

    Add or update the following line:

    password required pam_pwhistory.so use_authtok
  "
  impact 0.5
  tag severity: 'medium'
  tag gtitle: 'SRG-OS-000077-GPOS-00045'
  tag gid: 'V-PHTN-50-000243'
  tag rid: 'SV-PHTN-50-000243'
  tag stig_id: 'PHTN-50-000243'
  tag cci: ['CCI-000200']
  tag nist: ['IA-5 (1) (e)']

  describe file('/etc/pam.d/system-password') do
    its('content') { should match /^password\s+(required|requisite)\s+pam_pwhistory\.so\s+(?=.*\buse_authtok\b).*$/ }
    its('content') { should_not match /^password\s+(required|requisite)\s+pam_pwhistory\.so\s+(?=.*\bconf\b).*$/ }
    its('content') { should_not match /^password\s+(required|requisite)\s+pam_pwhistory\.so\s+(?=.*\bfile\b).*$/ }
  end
end
