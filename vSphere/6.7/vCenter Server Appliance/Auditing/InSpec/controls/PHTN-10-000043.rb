control "PHTN-10-000043" do
  title "The Photon operating system messages file must have mode 0640 or less
permissive."
  desc  "Only authorized personnel should be aware of errors and the details of
the errors. Error messages are an indicator of an organization's operational
state and can provide sensitive information to an unprivileged attacker."
  tag severity: nil
  tag gtitle: "SRG-OS-000206-GPOS-00084"
  tag gid: nil
  tag rid: "PHTN-10-000043"
  tag stig_id: "PHTN-10-000043"
  tag fix_id: nil
  tag cci: "CCI-001314"
  tag nist: ["SI-11 b", "Rev_4"]
  tag false_negatives: nil
  tag false_positives: nil
  tag documentable: nil
  tag mitigations: nil
  tag severity_override_guidance: nil
  tag potential_impacts: nil
  tag third_party_tools: nil
  tag mitigation_controls: nil
  tag responsibility: nil
  tag ia_controls: "SI-11 b"
  tag check: "At the command line, execute the following command:

# stat -c \"%n permissions are %a\" /var/log/vmware/messages

If the permissions on the file are more permissive than 0640, this is a
finding."
  tag fix: "At the command line, execute the following command:

# chmod 0640 /var/log/vmware/messages"

  describe file('/var/log/vmware/messages') do
    it { should_not be_more_permissive_than('0640') }
  end

end

