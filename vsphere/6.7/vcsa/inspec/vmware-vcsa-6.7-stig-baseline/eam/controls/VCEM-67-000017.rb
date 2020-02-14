control "VCEM-67-000017" do
  title "ESX Agent Manager directory tree must have permissions in an \"out of
the box\" state."
  desc  "As a rule, accounts on a web server are to be kept to a minimum. Only
administrators, web managers, developers, auditors, and web authors require
accounts on the machine hosting the web server. The resources to which these
accounts have access must also be closely monitored and controlled. ESX Agent
Manager files must be adequately protected with correct permissions as applied
\"out of the box\"."
  impact 0.5
  tag severity: "CAT II"
  tag gtitle: "SRG-APP-000211-WSR-000030"
  tag gid: nil
  tag rid: "VCEM-67-000017"
  tag stig_id: "VCEM-67-000017"
  tag cci: "CCI-001082"
  tag nist: ["SC-2", "Rev_4"]
  desc 'check', "At the command prompt, execute the following command:

# find /usr/lib/vmware-eam/web/ -xdev -type f -a '(' -not -user eam -o -not
-group cis ')' -exec ls -ld {} \\;

If the command produces any output, this is a finding."
  desc 'fix', "At the command prompt, execute the following command:

# chown eam:cis <file_name>

Repeat the command for each file that was returned

Note: Replace <file_name> for the name of the file that was returned."

  describe command('find /usr/lib/vmware-eam/web/ -xdev -type f -a \'(\' -not -user eam -o -not -group cis \')\' -exec ls -ld {} \;') do
   its('stdout.strip') { should eq ''}
  end

end

