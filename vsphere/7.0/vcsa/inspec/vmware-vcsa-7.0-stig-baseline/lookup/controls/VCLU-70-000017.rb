control 'VCLU-70-000017' do
  title 'Lookup Service directory tree must have permissions in an out-of-the-box state.'
  desc 'As a rule, accounts on a web server are to be kept to a minimum. Only administrators, web managers, developers, auditors, and web authors require accounts on the machine hosting the web server. The resources to which these accounts have access must also be closely monitored and controlled. Lookup Service files must be adequately protected with correct permissions as applied out of the box.

'
  desc 'check', "At the command prompt, run the following command:

# find  /usr/lib/vmware-lookupsvc/lib  /usr/lib/vmware-lookupsvc/conf -xdev -type f -a '(' -perm -o+w -o -not -user root -o -not -group root ')' -exec ls -ld {} \\;

If the command produces any output, this is a finding."
  desc 'fix', 'At the command prompt, run the following commands:

# chmod o-w <file>
# chown root:root <file>

Repeat the command for each file that was returned.'
  impact 0.5
  tag check_id: 'C-60397r888755_chk'
  tag severity: 'medium'
  tag gid: 'V-256722'
  tag rid: 'SV-256722r888757_rule'
  tag stig_id: 'VCLU-70-000017'
  tag gtitle: 'SRG-APP-000211-WSR-000030'
  tag fix_id: 'F-60340r888756_fix'
  tag satisfies: ['SRG-APP-000211-WSR-000030', 'SRG-APP-000380-WSR-000072']
  tag cci: ['CCI-001082', 'CCI-001813']
  tag nist: ['SC-2', 'CM-5 (1) (a)']

  describe command("find '#{input('rootPath')}' /usr/lib/vmware-lookupsvc/conf -xdev -type f -a \'(\' -perm -o+w -o -not -user root -o -not -group root \')\' -exec ls -ld {} \\;") do
    its('stdout.strip') { should eq '' }
  end
end
