control "PHTN-10-000075" do
  title "The Photon operating system must use the pam_cracklib module."
  desc  "If the operating system allows the user to select passwords based on
dictionary words, then this increases the chances of password compromise by
increasing the opportunity for successful guesses and brute-force attacks."
  tag severity: nil
  tag gtitle: "SRG-OS-000480-GPOS-00225"
  tag gid: nil
  tag rid: "PHTN-10-000075"
  tag stig_id: "PHTN-10-000075"
  tag fix_id: nil
  tag cci: "CCI-000366"
  tag nist: ["CM-6 b", "Rev_4"]
  tag false_negatives: nil
  tag false_positives: nil
  tag documentable: nil
  tag mitigations: nil
  tag severity_override_guidance: nil
  tag potential_impacts: nil
  tag third_party_tools: nil
  tag mitigation_controls: nil
  tag responsibility: nil
  tag ia_controls: "CM-6 b"
  tag check: "At the command line, execute the following command:

# grep pam_cracklib /etc/pam.d/system-password

If the output does not return at least \"password  requisite
pam_cracklib.so\", this is a finding."
  tag fix: "Open /etc/pam.d/system-password with a text editor.

Add the following, replacing any existing 'pam_cracklib.so' line :

password requisite pam_cracklib.so dcredit=-1 ucredit=-1 lcredit=-1 ocredit=-1
minlen=8 minclass=4 difok=4 retry=3 maxsequence=0 enforce_for_root"

  describe file ('/etc/pam.d/system-password') do
      its ('content'){should match /^(?=.*?\bpassword\b)(?=.*?\brequisite\b)(?=.*?\bpam_cracklib.so\b).*$/}
  end

end

