control "VCFL-67-000019" do
  title "vSphere Client directory tree must have permissions in an \"out of the
box\" state."
  desc  "As a rule, accounts on a web server are to be kept to a minimum. Only
administrators, web managers, developers, auditors, and web authors require
accounts on the machine hosting the web server. The resources to which these
accounts have access must also be closely monitored and controlled. vSphere
Client files must be adequately protected with correct permissions as applied
\"out of the box\"."
  impact 0.5
  tag severity: "CAT II"
  tag gtitle: "SRG-APP-000211-WSR-000030"
  tag gid: nil
  tag rid: "VCFL-67-000019"
  tag stig_id: "VCFL-67-000019"
  tag cci: "CCI-001082"
  tag nist: ["SC-2", "Rev_4"]
  desc 'check', "At the command prompt, execute the following command:

# find /usr/lib/vmware-vsphere-client/server -xdev -type f -a '(' -not -user
vsphere-client -o '(' -not -group root -a -not -group users -not -group cis ')'
')' -exec ls -ld {} \\;

If the command produces any output, this is a finding."
  desc 'fix', "At the command prompt, execute the following command:

#chown vsphere-client:root <file_name>

Repeat the command for each file that was returned

Note: Replace <file_name> for the name of the file that was returned."

=begin  this was too slow with 8000 files
  groups = ["root", "users", "cis"]
  command('find /usr/lib/vmware-vsphere-client/server -type f -xdev').stdout.split.each do | fname |
    describe file(fname) do
      its('owner') {should eq 'vsphere-client'}
      its('group') {should be_in groups}
    end
  end
=end

  describe command('find /usr/lib/vmware-vsphere-client/server -xdev -type f -a \'(\' -not -user vsphere-client -o \'(\' -not -group root -a -not -group users -not -group cis \')\' \')\' -exec ls -ld {} \;') do
   its('stdout.strip') { should eq ''}
  end

end