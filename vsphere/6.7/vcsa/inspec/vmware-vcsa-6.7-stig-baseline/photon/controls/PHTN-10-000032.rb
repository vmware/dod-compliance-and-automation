control "PHTN-10-000032" do
  title "The Photon operating system must only allow installation of packages
signed by VMware."
  desc  "Installation of any non-trusted software, patches, service packs,
device drivers or operating system components can significantly affect the
overall security of the operating system. This requirement ensures the software
has not been tampered and has been provided by VMware. "
  impact 0.5
  tag severity: "CAT II"
  tag gtitle: "SRG-OS-000095-GPOS-00049"
  tag gid: nil
  tag rid: "PHTN-10-000032"
  tag stig_id: "PHTN-10-000032"
  tag cci: "CCI-000381"
  tag nist: ["CM-7 a", "Rev_4"]
  desc 'check', "At the command line, execute the following command:

# rpm -qa gpg-pubkey --qf \"%{version}-%{release} %{summary}\
\"|grep -v \"66fd4949-4803fe57\"

If there is any output, an unsupported package has been installed, this is a
finding"
  desc 'fix', "Confirm with VMware support that this package is not supported (for
potential package additions after STIG publication) then At the command line,
execute the following command:

# rpm -e <package-name-from-check>"

  describe command('rpm -qa gpg-pubkey --qf "%{version}-%{release} %{summary}\n"|grep -v "66fd4949-4803fe57"') do
      its ('stdout') { should eq '' }
  end

end

