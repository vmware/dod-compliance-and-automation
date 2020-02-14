control "VCPF-67-000016" do
  title "Performance Charts directory tree must have permissions in an \"out of
the box\" state."
  desc  "As a rule, accounts on a web server are to be kept to a minimum. Only
administrators, web managers, developers, auditors, and web authors require
accounts on the machine hosting the web server. The resources to which these
accounts have access must also be closely monitored and controlled. Performance
Charts files must be adequately protected with correct permissions as applied
\"out of the box\"."
  impact 0.5
  tag severity: "CAT II"
  tag gtitle: "SRG-APP-000211-WSR-000030"
  tag gid: nil
  tag rid: "VCPF-67-000016"
  tag stig_id: "VCPF-67-000016"
  tag cci: "CCI-001082"
  tag nist: ["SC-2", "Rev_4"]
  desc 'check', "At the command prompt, execute the following command:

# find /usr/lib/vmware-perfcharts/tc-instance/webapps/ -xdev -type f -a '('
-not -user perfcharts -o -not -group cis ')' -exec ls -A {} \\;

Expected result:

/usr/lib/vmware-perfcharts/tc-instance/webapps/statsreport/WEB-INF/web.xml

If the command does not produce output, this is NOT a finding. If the output of
the command does not match the expected result, this is a finding."
  desc 'fix', "At the command prompt, execute the following command:

# chown perfcharts:cis <file_name>

Repeat the command for each file that was returned

Note: Replace <file_name> for the name of the file that was returned.
"

  describe command('find /usr/lib/vmware-perfcharts/tc-instance/webapps/ -xdev -type f -a \'(\' -not -user perfcharts -o -not -group cis \')\' -exec ls -A {} \;') do
   its('stdout.strip') { should eq '/usr/lib/vmware-perfcharts/tc-instance/webapps/statsreport/WEB-INF/web.xml'}
  end

end

