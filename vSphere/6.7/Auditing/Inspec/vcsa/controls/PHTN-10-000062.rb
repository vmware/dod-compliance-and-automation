control "PHTN-10-000062" do
  title "The Photon operating system RPM package management tool must
cryptographically verify the authenticity of all software packages during
installation."
  desc  "Installation of any non-trusted software, patches, service packs,
device drivers or operating system components can significantly affect the
overall security of the operating system. Ensuring all packages' cryptographic
signatures are valid prior to installation ensures the provenance of the
software and protects against malicious tampering."
  tag severity: nil
  tag gtitle: "SRG-OS-000366-GPOS-00153"
  tag gid: nil
  tag rid: "PHTN-10-000062"
  tag stig_id: "PHTN-10-000062"
  tag fix_id: nil
  tag cci: "CCI-001749"
  tag nist: ["CM-5 (3)", "Rev_4"]
  tag false_negatives: nil
  tag false_positives: nil
  tag documentable: nil
  tag mitigations: nil
  tag severity_override_guidance: nil
  tag potential_impacts: nil
  tag third_party_tools: nil
  tag mitigation_controls: nil
  tag responsibility: nil
  tag ia_controls: "CM-5 (3)"
  tag check: "At the command line, execute the following command:

# grep -s nosignature /usr/lib/rpm/rpmrc /etc/rpmrc ~root/.rpmrc

If the command returns any output, this is a finding."
  tag fix: "Open the file containing 'nosignature' with a text editor and
remove the option."

  describe command('grep -s nosignature /usr/lib/rpm/rpmrc /etc/rpmrc ~root/.rpmrc') do
      its ('stdout') { should eq '' }
  end

end

