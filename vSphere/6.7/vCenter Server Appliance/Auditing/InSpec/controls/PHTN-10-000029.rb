control "PHTN-10-000029" do
  title "The Photon operating system must prohibit password reuse for a minimum
of five generations."
  desc  "Password complexity, or strength, is a measure of the effectiveness of
a password in resisting attempts at guessing and brute-force attacks. If the
information system or application allows the user to consecutively reuse their
password when that password has exceeded its defined lifetime, the end result
is a password that is not changed as per policy requirements."
  tag severity: nil
  tag gtitle: "SRG-OS-000077-GPOS-00045"
  tag gid: nil
  tag rid: "PHTN-10-000029"
  tag stig_id: "PHTN-10-000029"
  tag fix_id: nil
  tag cci: "CCI-000200"
  tag nist: ["IA-5 (1) (e)", "Rev_4"]
  tag false_negatives: nil
  tag false_positives: nil
  tag documentable: nil
  tag mitigations: nil
  tag severity_override_guidance: nil
  tag potential_impacts: nil
  tag third_party_tools: nil
  tag mitigation_controls: nil
  tag responsibility: nil
  tag ia_controls: "IA-5 (1) (e)"
  tag check: "At the command line, execute the following command:

# grep pam_pwhistory /etc/pam.d/system-password|grep --color=always
\"remember=.\"

Expected result:

password required pam_pwhistory.so enforce_for_root use_authtok remember=5
retry=3

If the output does not match the expected result, this is a finding.
"
  tag fix: "Open /etc/pam.d/system-password with a text editor.

Add the following line after the last auth statement:

password required pam_pwhistory.so enforce_for_root use_authtok remember=5
retry=3

"

  describe file ('/etc/pam.d/system-password') do
      its ('content'){should match /^(?=.*?\bpassword\b)(?=.*?\brequired\b)(?=.*?\bpam_pwhistory.so\b)(?=.*?\bremember=5\b).*$/}
  end

end

