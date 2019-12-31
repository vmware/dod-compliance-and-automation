control "PHTN-10-000077" do
  title "The Photon operating system must enforce a delay of at least 4 seconds
between logon prompts following a failed logon attempt."
  desc  "Limiting the number of logon attempts over a certain time interval
reduces the chances that an unauthorized user may gain access to an account."
  tag severity: nil
  tag gtitle: "SRG-OS-000480-GPOS-00226"
  tag gid: nil
  tag rid: "PHTN-10-000077"
  tag stig_id: "PHTN-10-000077"
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

# grep pam_faildelay /etc/pam.d/system-auth|grep --color=always \"delay=\"

Expected result:

auth optional pam_faildelay.so delay=4000000

If the output does not match the expected result, this is a finding."
  tag fix: "Open /etc/pam.d/system-auth with a text editor.

Remove any existing pam_faildelay line and add the follwing line at the end of
the file:

auth optional pam_faildelay.so delay=4000000"

  describe file ('/etc/pam.d/system-auth') do
      its ('content'){should match /^(?=.*?\bauth\b)(?=.*?\boptional\b)(?=.*?\bpam_faildelay.so\b)(?=.*?\bdelay=4000000\b).*$/}
  end

end

