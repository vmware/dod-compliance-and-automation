control "PHTN-10-000117" do
  title "The Photon operating system must enforce password complexity on the
root account."
  desc  "Password complexity rules must apply to all accounts on the system,
including root. Without specifying the enforce_for_root flag, pam_cracklib does
not apply complexity rules to the root user. While root users can find way
around this requirement, give it's superuser power, it is necessary to attempt
to force compliance."
  impact 0.5
  tag severity: "CAT II"
  tag gtitle: "SRG-OS-000480-GPOS-00227"
  tag gid: nil
  tag rid: "PHTN-10-000117"
  tag stig_id: "PHTN-10-000117"
  tag cci: "CCI-000366"
  tag nist: ["CM-6 b", "Rev_4"]
  desc 'check', "At the command line, execute the following command:

# grep pam_cracklib /etc/pam.d/system-password|grep --color=always
\"enforce_for_root\"

Expected result:

password requisite pam_cracklib.so dcredit=-1 ucredit=-1 lcredit=-1 ocredit=-1
minlen=8 minclass=4 difok=4 retry=3 maxsequence=0 enforce_for_root

If the output does not match the expected result, this is a finding."
  desc 'fix', "Open /etc/pam.d/system-password with a text editor.

Add the following, replacing any existing 'pam_cracklib.so' line :

password requisite pam_cracklib.so dcredit=-1 ucredit=-1 lcredit=-1 ocredit=-1
minlen=8 minclass=4 difok=4 retry=3 maxsequence=0 enforce_for_root"

  describe file ('/etc/pam.d/system-password') do
      its ('content'){should match /^(?=.*?\bpassword\b)(?=.*?\brequisite\b)(?=.*?\benforce_for_root\b).*$/}
  end

end

