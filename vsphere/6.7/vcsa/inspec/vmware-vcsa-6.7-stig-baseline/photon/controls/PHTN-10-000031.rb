control "PHTN-10-000031" do
  title "The Photon operating system must enforce a minimum 8-character
password length."
  desc  "The shorter the password, the lower the number of possible
combinations that need to be tested before the password is compromised.

    Password complexity, or strength, is a measure of the effectiveness of a
password in resisting attempts at guessing and brute-force attacks. Password
length is one factor of several that helps to determine strength and how long
it takes to crack a password. Use of more characters in a password helps to
exponentially increase the time and/or resources required to compromise the
password."
  impact 0.5
  tag severity: "CAT II"
  tag gtitle: "SRG-OS-000078-GPOS-00046"
  tag gid: nil
  tag rid: "PHTN-10-000031"
  tag stig_id: "PHTN-10-000031"
  tag cci: "CCI-000205"
  tag nist: ["IA-5 (1) (a)", "Rev_4"]
  desc 'check', "At the command line, execute the following command:

# grep pam_cracklib /etc/pam.d/system-password|grep --color=always \"minlen=..\"

Expected result:

password requisite pam_cracklib.so dcredit=-1 ucredit=-1 lcredit=-1 ocredit=-1
minlen=8 minclass=4 difok=4 retry=3 maxsequence=0 enforce_for_root

If the output does not match the expected result, this is a finding."
  desc 'fix', "Open /etc/pam.d/system-password with a text editor.

Add the following, replacing any existing 'pam_cracklib.so' line :

password requisite pam_cracklib.so dcredit=-1 ucredit=-1 lcredit=-1 ocredit=-1
minlen=8 minclass=4 difok=4 retry=3 maxsequence=0 enforce_for_root"

  describe file ('/etc/pam.d/system-password') do
      its ('content'){should match /^(?=.*?\bpassword\b)(?=.*?\brequisite\b)(?=.*?\bpam_cracklib.so\b)(?=.*?\bminlen=8\b).*$/}
  end

end

