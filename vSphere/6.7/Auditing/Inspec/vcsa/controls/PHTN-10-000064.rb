control "PHTN-10-000064" do
  title "The Photon operating system RPM package management tool must
cryptographically verify the authenticity of all software packages during
installation."
  desc  "Installation of any non-trusted software, patches, service packs,
device drivers or operating system components can significantly affect the
overall security of the operating system. This requirement ensures the software
has not been tampered and has been provided by a trusted vendor. "
  tag severity: nil
  tag gtitle: "SRG-OS-000366-GPOS-00153"
  tag gid: nil
  tag rid: "PHTN-10-000064"
  tag stig_id: "PHTN-10-000064"
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

# grep gpgcheck /etc/yum.repos.d/*

If \"gpgcheck\" is not set to \"1\" in any returned file, this is a finding."
  tag fix: "Open the file where gpgcheck is not set to 1 with a text editor.
Remove any existing gpgcheck setting and add the following line at the end of
the file:

gpgcheck=1"

  command('find /etc/yum.repos.d/ -type f').stdout.split.each do | repofile |
    describe file (repofile) do
      its ('content'){should match /^(?=.*?\bgpgcheck=1\b).*$/}
    end
  end

end

