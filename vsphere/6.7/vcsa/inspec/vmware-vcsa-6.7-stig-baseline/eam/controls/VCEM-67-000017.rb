control 'VCEM-67-000017' do
  title "ESX Agent Manager directory tree must have permissions in an
\"out-of-the box\" state."
  desc  "As a rule, accounts on a web server are to be kept to a minimum. Only
administrators, web managers, developers, auditors, and web authors require
accounts on the machine hosting the web server. The resources to which these
accounts have access must also be closely monitored and controlled. ESX Agent
Manager files must be adequately protected with correct permissions as applied
\"out of the box\".
  "
  desc  'rationale', ''
  desc  'check', "
    At the command prompt, execute the following command:

    # find /usr/lib/vmware-eam/web/ -xdev -type f -a '(' -not -user eam -o -not
-group cis ')' -exec ls -ld {} \\;

    If the command produces any output, this is a finding.
  "
  desc 'fix', "
    At the command prompt, execute the following command:

    # chown eam:cis <file_name>

    Repeat the command for each file that was returned.

    Note: Replace <file_name> for the name of the file that was returned.
  "
  impact 0.5
  tag severity: 'medium'
  tag gtitle: 'SRG-APP-000211-WSR-000030'
  tag satisfies: ['SRG-APP-000211-WSR-000030', 'SRG-APP-000380-WSR-000072']
  tag gid: 'V-239388'
  tag rid: 'SV-239388r674658_rule'
  tag stig_id: 'VCEM-67-000017'
  tag fix_id: 'F-42580r674657_fix'
  tag cci: ['CCI-001082', 'CCI-001813']
  tag nist: ['SC-2', 'CM-5 (1)']

  describe command("find '#{input('rootPath')}' -xdev -type f -a \'(\' -not -user eam -o -not -group cis \')\' -exec ls -ld {} \\;") do
    its('stdout.strip') { should eq '' }
  end
end
