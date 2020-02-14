control "VCUI-67-000008" do
  title "vSphere UI application files must be verified for their integrity."
  desc  "Verifying that the vSphere UI application code is unchanged from it's
shipping state is essential for file validation and non-repudiation of the
vSphere UI itself. There is no reason that the MD5 hash of the rpm original
files should be changed after installation, excluding configuration files."
  impact 0.5  
  tag severity: "CAT II"
  tag gtitle: "SRG-APP-000358-WSR-000163"
  tag gid: nil
  tag rid: "VCUI-67-000008"
  tag stig_id: "VCUI-67-000008"
  tag cci: "CCI-001851"
  tag nist: ["AU-4 (1)", "Rev_4"]
  desc 'check', "At the command prompt, execute the following command:

# rpm -V vsphere-ui|grep \"^..5......\"|grep -E \"\\.war|\\.jar|\\.sh|\\.py\"

If is any output, this is a finding."
  desc 'fix', "Re-install the VCSA or roll back to a snapshot. Modifying the
vSphere UI installation files manually is not supported by VMware."

  describe command('rpm -V vsphere-ui|grep "^..5......"|grep -E "\.war|\.jar|\.sh|\.py"') do
    its ('stdout.strip') { should eq '' }
  end

end