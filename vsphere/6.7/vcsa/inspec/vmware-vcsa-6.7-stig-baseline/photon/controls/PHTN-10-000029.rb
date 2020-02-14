control "PHTN-10-000029" do
  title "The Photon operating system must prohibit password reuse for a minimum
of five generations."
  desc  "Password complexity, or strength, is a measure of the effectiveness of
a password in resisting attempts at guessing and brute-force attacks. If the
information system or application allows the user to consecutively reuse their
password when that password has exceeded its defined lifetime, the end result
is a password that is not changed as per policy requirements."
  impact 0.5
  tag severity: "CAT II"
  tag gtitle: "SRG-OS-000077-GPOS-00045"
  tag gid: nil
  tag rid: "PHTN-10-000029"
  tag stig_id: "PHTN-10-000029"
  tag cci: "CCI-000200"
  tag nist: ["IA-5 (1) (e)", "Rev_4"]
  desc 'check', "At the command line, execute the following command:

# grep pam_pwhistory /etc/pam.d/system-password|grep --color=always
\"remember=.\"

Expected result:

password required pam_pwhistory.so enforce_for_root use_authtok remember=5
retry=3

If the output does not match the expected result, this is a finding.
"
  desc 'fix', "Open /etc/pam.d/system-password with a text editor.

Add the following line after the last auth statement:

password required pam_pwhistory.so enforce_for_root use_authtok remember=5
retry=3

"

  describe file ('/etc/pam.d/system-password') do
      its ('content'){should match /^(?=.*?\bpassword\b)(?=.*?\brequired\b)(?=.*?\bpam_pwhistory.so\b)(?=.*?\bremember=5\b).*$/}
  end

end

