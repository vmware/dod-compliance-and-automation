control "PHTN-10-000063" do
  title "The Photon operating system RPM package management tool must
cryptographically verify the authenticity of all software packages during
installation."
  desc  "Installation of any non-trusted software, patches, service packs,
device drivers or operating system components can significantly affect the
overall security of the operating system. This requirement ensures the software
has not been tampered and has been provided by a trusted vendor. "
  impact 0.5
  tag severity: "CAT II"
  tag gtitle: "SRG-OS-000366-GPOS-00153"
  tag gid: nil
  tag rid: "PHTN-10-000063"
  tag stig_id: "PHTN-10-000063"
  tag cci: "CCI-001749"
  tag nist: ["CM-5 (3)", "Rev_4"]
  desc 'check', "At the command line, execute the following command:

# grep \"^gpgcheck\" /etc/tdnf/tdnf.conf

If \"gpgcheck\" is not set to \"1\", this is a finding."
  desc 'fix', "Open /etc/tdnf/tdnf.conf with a text editor. Remove any existing
gpgcheck setting and add the following line:

gpgcheck=1"

  describe command('grep "^gpgcheck" /etc/tdnf/tdnf.conf') do
      its ('stdout.strip') { should cmp 'gpgcheck=1' }
  end

end

