control "PHTN-10-000022" do
  title "The Photon operating system must enforce password complexity by
requiring that at least one lower-case character be used."
  desc  "Use of a complex password helps to increase the time and resources
required to compromise the password. Password complexity, or strength, is a
measure of the effectiveness of a password in resisting attempts at guessing
and brute-force attacks."
  impact 0.5
  tag severity: "CAT II"
  tag gtitle: "SRG-OS-000070-GPOS-00038"
  tag gid: nil
  tag rid: "PHTN-10-000022"
  tag stig_id: "PHTN-10-000022"
  tag cci: "CCI-000193"
  tag nist: ["IA-5 (1) (a)", "Rev_4"]
  desc 'check', "At the command line, execute the following command:

# grep pam_cracklib /etc/pam.d/system-password|grep --color=always
\"lcredit=..\"

Expected result:

password requisite pam_cracklib.so dcredit=-1 ucredit=-1 lcredit=-1 ocredit=-1
minlen=8 minclass=4 difok=4 retry=3 maxsequence=0 enforce_for_root

If the output does not match the expected result, this is a finding."
  desc 'fix', "Open /etc/pam.d/system-password with a text editor.

Add the following, replacing any existing 'pam_cracklib.so' line :

password requisite pam_cracklib.so dcredit=-1 ucredit=-1 lcredit=-1 ocredit=-1
minlen=8 minclass=4 difok=4 retry=3 maxsequence=0 enforce_for_root"

  describe file ('/etc/pam.d/system-password') do
    its ('content'){should match /^(?=.*?\bpassword\b)(?=.*?\brequisite\b)(?=.*?\blcredit=-1\b).*$/}
  end

end

