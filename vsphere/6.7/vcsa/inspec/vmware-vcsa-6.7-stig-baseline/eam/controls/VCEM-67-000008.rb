control "VCEM-67-000008" do
  title "ESX Agent Manager application files must be verified for their
integrity."
  desc  "Verifying that ESX Agent Manager application code is unchanged from
it's shipping state is essential for file validation and non-repudiation of the
ESX Agent Manager itself. There is no reason that the MD5 hash of the rpm
original files should be changed after installation, excluding configuration
files."
  impact 0.5
  tag severity: "CAT II"
  tag gtitle: "SRG-APP-000131-WSR-000051"
  tag gid: nil
  tag rid: "VCEM-67-000008"
  tag stig_id: "VCEM-67-000008"
  tag cci: "CCI-001749"
  tag nist: ["CM-5 (3)", "Rev_4"]
  desc 'check', "At the command prompt, execute the following command:

# rpm -V vmware-eam|grep \"^..5......\"|grep -E \"\\.war|\\.jar|\\.sh|\\.py\"

If is any output, this is a finding."
  desc 'fix', "Re-install the VCSA or roll back to a snapshot. Modifying the EAM
installation files manually is not supported by VMware."

  describe command('rpm -V vmware-eam|grep "^..5......"|grep -E "\.war|\.jar|\.sh|\.py"') do
    its ('stdout.strip') { should eq '' }
  end

end

