control "VCFL-67-000012" do
  title "vSphere Client application files must be verified for their integrity."
  desc  "Verifying that vSphere Client application code is unchanged from it's
shipping state is essential for file validation and non-repudiation of  vSphere
Client itself. There is no reason that the MD5 hash of the rpm original files
should be changed after installation, excluding configuration files."
  impact 0.5
  tag severity: "CAT II"
  tag gtitle: "SRG-APP-000131-WSR-000051"
  tag gid: nil
  tag rid: "VCFL-67-000012"
  tag stig_id: "VCFL-67-000012"
  tag cci: "CCI-001749"
  tag nist: ["CM-5 (3)", "Rev_4"]
  desc 'check', "At the command prompt, execute the following command:

# rpm -V vsphere-client|grep \"^..5......\"|grep -E
\"\\.war|\\.jar|\\.sh|\\.py\"

If is any output, this is a finding."
  desc 'fix', "Re-install the VCSA or roll back to a snapshot. Modifying the
vSphere Client installation files manually is not supported by VMware."

  describe command('rpm -V vsphere-client|grep "^..5......"|grep -E "\.war|\.jar|\.sh|\.py"') do
    its ('stdout.strip') { should eq '' }
  end

end