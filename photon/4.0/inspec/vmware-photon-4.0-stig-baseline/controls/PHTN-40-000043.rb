control 'PHTN-40-000043' do
  title 'The Photon operating system must prohibit password reuse for a minimum of five generations.'
  desc  'Password complexity, or strength, is a measure of the effectiveness of a password in resisting attempts at guessing and brute-force attacks. If the information system or application allows the user to consecutively reuse their password when that password has exceeded its defined lifetime, the end result is a password that is not changed as per policy requirements.'
  desc  'rationale', ''
  desc  'check', "
    At the command line, run the following command to verify password reuse for a minimum of five generations is prohibited:

    # grep ^password /etc/pam.d/system-password

    Example result:

    password required pam_pwhistory.so remember=5 retry=3 enforce_for_root use_authtok
    password required pam_pwquality.so use_authtok
    password required pam_unix.so sha512 shadow use_authtok

    If the pam_pwhistory.so module is not present with a parameter of \"remember=5\", this is a finding.
  "
  desc 'fix', "
    Navigate to and open:

    /etc/pam.d/system-password

    Add or update the following line:

    password required pam_pwhistory.so remember=5 retry=3 enforce_for_root use_authtok
  "
  impact 0.5
  tag severity: 'medium'
  tag gtitle: 'SRG-OS-000077-GPOS-00045'
  tag gid: 'V-PHTN-40-000043'
  tag rid: 'SV-PHTN-40-000043'
  tag stig_id: 'PHTN-40-000043'
  tag cci: ['CCI-000200']
  tag nist: ['IA-5 (1) (e)']

  describe pam('/etc/pam.d/system-password') do
    its('lines') { should match_pam_rule('password required pam_pwhistory.so') }
    its('lines') { should match_pam_rule('password required pam_pwhistory.so').all_with_integer_arg('remember', '==', 5) }
  end
end
