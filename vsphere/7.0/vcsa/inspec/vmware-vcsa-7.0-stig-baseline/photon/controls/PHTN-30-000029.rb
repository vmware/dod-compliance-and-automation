# encoding: UTF-8

control 'PHTN-30-000029' do
  title "The Photon operating system must prohibit password reuse for a minimum
of five generations."
  desc  "Password complexity, or strength, is a measure of the effectiveness of
a password in resisting attempts at guessing and brute-force attacks. If the
information system or application allows the user to consecutively reuse their
password when that password has exceeded its defined lifetime, the end result
is a password that is not changed as per policy requirements."
  desc  'rationale', ''
  desc  'check', "
    At the command line, execute the following command:

    # grep pam_pwhistory /etc/pam.d/system-password|grep --color=always
\"remember=.\"

    Expected result:

    password requisite pam_pwhistory.so enforce_for_root use_authtok remember=5
retry=3

    If the output does not match the expected result, this is a finding.
  "
  desc  'fix', "
    Navigate to and open:

    /etc/pam.d/system-password

    Add the following line after the \"password requisite pam_cracklib.so\"
statement:

    password requisite pam_pwhistory.so enforce_for_root use_authtok remember=5
retry=3
  "
  impact 0.5
  tag severity: 'medium'
  tag gtitle: 'SRG-OS-000077-GPOS-00045'
  tag gid: nil
  tag rid: nil
  tag stig_id: 'PHTN-30-000029'
  tag fix_id: nil
  tag cci: 'CCI-000200'
  tag nist: ['IA-5 (1) (e)']

  describe.one do
  
    describe file ('/etc/pam.d/system-password') do
        its ('content'){should match /^(?=.*?\bpassword\b)(?=.*?\brequisite\b)(?=.*?\bpam_pwhistory.so\b)(?=.*?\benforce_for_root use_authtok remember=5 retry=3\b).*$/}
    end

    describe file ('/etc/pam.d/system-password') do
        its ('content'){should match /^(?=.*?\bpassword\b)(?=.*?\brequisite\b)(?=.*?\bpam_pwhistory.so\b)(?=.*?\benforce_for_root use_authtok retry=3 remember=5\b).*$/}
    end

  end

end

