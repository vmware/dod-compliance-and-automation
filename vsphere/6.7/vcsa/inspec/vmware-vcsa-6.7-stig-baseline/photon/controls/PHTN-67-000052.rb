control 'PHTN-67-000052' do
  title "The Photon operating system must enforce password complexity by
requiring that at least one special character be used."
  desc  "Use of a complex password helps to increase the time and resources
required to compromise the password. Password complexity, or strength, is a
measure of the effectiveness of a password in resisting attempts at guessing
and brute-force attacks."
  desc  'rationale', ''
  desc  'check', "
    At the command line, execute the following command:

    # grep pam_cracklib /etc/pam.d/system-password|grep --color=always
\"ocredit=..\"

    Expected result:

    password requisite pam_cracklib.so dcredit=-1 ucredit=-1 lcredit=-1
ocredit=-1 minlen=8 minclass=4 difok=4 retry=3 maxsequence=0 enforce_for_root

    If the output does not match the expected result, this is a finding.
  "
  desc 'fix', "
    Open /etc/applmgmt/appliance/system-password with a text editor.

    Comment out any existing \"pam_cracklib.so\" line and add the following:

    password requisite pam_cracklib.so dcredit=-1 ucredit=-1 lcredit=-1
ocredit=-1 minlen=8 minclass=4 difok=4 retry=3 maxsequence=0 enforce_for_root

    Save and close.
  "
  impact 0.5
  tag severity: 'medium'
  tag gtitle: 'SRG-OS-000266-GPOS-00101'
  tag gid: 'V-239123'
  tag rid: 'SV-239123r816636_rule'
  tag stig_id: 'PHTN-67-000052'
  tag fix_id: 'F-42293r816635_fix'
  tag cci: ['CCI-001619']
  tag nist: ['IA-5 (1) (a)']

  describe file('/etc/pam.d/system-password') do
    its('content') { should match /^(?=.*?\bpassword\b)(?=.*?\brequisite\b)(?=.*?\bocredit=-1\b).*$/ }
  end
end
