control "PHTN-10-000063" do
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
  tag rid: "PHTN-10-000063"
  tag stig_id: "PHTN-10-000063"
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

# grep \"^gpgcheck\" /etc/tdnf/tdnf.conf

If \"gpgcheck\" is not set to \"1\", this is a finding."
  tag fix: "Open /etc/tdnf/tdnf.conf with a text editor. Remove any existing
gpgcheck setting and add the following line:

gpgcheck=1"

  describe command('grep "^gpgcheck" /etc/tdnf/tdnf.conf') do
      its ('stdout.strip') { should cmp 'gpgcheck=1' }
  end

end

