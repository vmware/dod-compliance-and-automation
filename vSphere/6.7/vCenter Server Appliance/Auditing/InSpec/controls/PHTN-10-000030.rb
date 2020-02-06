control "PHTN-10-000030" do
  title "The Photon operating system must ensure that the old passwords are
being stored."
  desc  "Password complexity, or strength, is a measure of the effectiveness of
a password in resisting attempts at guessing and brute-force attacks. If the
information system or application allows the user to consecutively reuse their
password when that password has exceeded its defined lifetime, the end result
is a password that is not changed as per policy requirements."
  tag severity: nil
  tag gtitle: "SRG-OS-000077-GPOS-00045"
  tag gid: nil
  tag rid: "PHTN-10-000030"
  tag stig_id: "PHTN-10-000030"
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

# ls -al /etc/security/opasswd

If /etc/security/opasswd does not exist, this is a finding.

"
  tag fix: "At the command line, execute the following commands:

# touch /etc/security/opasswd
# chown root:root /etc/security/opasswd
# chmod 0600 /etc/security/opasswd"

  describe file('/etc/security/opasswd') do
    it { should exist }
  end

end

