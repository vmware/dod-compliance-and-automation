control "VCPF-67-000008" do
  title "Performance Charts application files must be verified for their
integrity."
  desc  "Verifying that the Security Token Service application code is
unchanged from it's shipping state is essential for file validation and
non-repudiation of Performance Charts itself. There is no reason that the MD5
hash of the rpm original files should be changed after installation, excluding
configuration files."
  impact 0.5
  tag severity: "CAT II"
  tag gtitle: "SRG-APP-000131-WSR-000051"
  tag gid: nil
  tag rid: "VCPF-67-000008"
  tag stig_id: "VCPF-67-000008"
  tag cci: "CCI-001749"
  tag nist: ["CM-5 (3)", "Rev_4"]
  desc 'check', "At the command prompt, execute the following command:

# rpm -V VMware-perfcharts|grep \"^..5......\"|grep \"/usr/lib\"|grep -v -E
\"\\.properties|\\.conf\"

If any files are returned, this is a finding."
  desc 'fix', "Re-install the VCSA or roll back to a snapshot. Modifying the
Performance Charts installation files manually is not supported by VMware."

  describe command('rpm -V VMware-perfcharts|grep "^..5......"|grep "/usr/lib"|grep -v -E "\.properties|\.conf"') do
    its ('stdout.strip') { should eq '' }
  end

end

