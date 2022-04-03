control 'VCFL-67-000019' do
  title "vSphere Client directory tree must have permissions in an
\"out-of-the-box\" state."
  desc "As a rule, accounts on a web server are to be kept to a minimum. Only
administrators, web managers, developers, auditors, and web authors require
accounts on the machine hosting the web server. The resources to which these
accounts have access must also be closely monitored and controlled. vSphere
Client files must be adequately protected with correct permissions as applied
out of the box.


  "
  desc  'rationale', ''
  desc  'check', "
    At the command prompt, execute the following command:

    # find /usr/lib/vmware-vsphere-client/server -xdev -type f -a '(' -not
-user vsphere-client -o '(' -not -group root -a -not -group users -not -group
cis ')' ')' -exec ls -ld {} \\;

    If the command produces any output, this is a finding.
  "
  desc 'fix', "
    At the command prompt, execute the following command:

    #chown vsphere-client:root <file_name>

    Repeat the command for each file that was returned.

    Note: Replace <file_name> for the name of the file that was returned.
  "
  impact 0.5
  tag severity: 'medium'
  tag gtitle: 'SRG-APP-000211-WSR-000030'
  tag satisfies: ['SRG-APP-000211-WSR-000030', 'SRG-APP-000380-WSR-000072']
  tag gid: 'V-239760'
  tag rid: 'SV-239760r679507_rule'
  tag stig_id: 'VCFL-67-000019'
  tag fix_id: 'F-42952r679506_fix'
  tag cci: ['CCI-001082', 'CCI-001813']
  tag nist: ['SC-2', 'CM-5 (1)']

  describe command('find /usr/lib/vmware-vsphere-client/server -xdev -type f -a \'(\' -not -user vsphere-client -o \'(\' -not -group root -a -not -group users -not -group cis \')\' \')\' -exec ls -ld {} \;') do
    its('stdout.strip') { should eq '' }
  end
end
