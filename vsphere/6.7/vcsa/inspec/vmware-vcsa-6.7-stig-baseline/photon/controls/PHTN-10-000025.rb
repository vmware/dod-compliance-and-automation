control "PHTN-10-000025" do
  title "The Photon operating system must store only encrypted representations
of passwords."
  desc  "Passwords must be protected at all times via strong, one way
encryption. If passwords are not encrypted, they can be plainly read (i.e.,
clear text) and easily compromised. If they are encrypted with a weak cipher,
those password are much more vulnerability to offline bute forcing attacks."
  impact 0.5
  tag severity: "CAT II"
  tag gtitle: "SRG-OS-000073-GPOS-00041"
  tag gid: nil
  tag rid: "PHTN-10-000025"
  tag stig_id: "PHTN-10-000025"
  tag cci: "CCI-000196"
  tag nist: ["IA-5 (1) (c)", "Rev_4"]
  desc 'check', "At the command line, execute the following command:

# grep password /etc/pam.d/system-password|grep --color=always \"sha512\"

If the output does not include \"sha512\", this is a finding."
  desc 'fix', "Open /etc/pam.d/system-password with a text editor.

Add the following argument (sha512) to the password line:
password required pam_unix.so sha512 shadow try_first_pass
"

  describe file ('/etc/pam.d/system-password') do
      its ('content'){should match /^(?=.*?\bpassword\b)(?=.*?\brequired\b)(?=.*?\bsha512\b).*$/}
  end

end

