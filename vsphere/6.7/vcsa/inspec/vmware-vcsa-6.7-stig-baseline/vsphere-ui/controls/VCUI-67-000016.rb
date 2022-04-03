control 'VCUI-67-000016' do
  title "vSphere UI directory tree must have permissions in an
\"out-of-the-box\" state."
  desc  "As a rule, accounts on a web server are to be kept to a minimum. Only
administrators, web managers, developers, auditors, and web authors require
accounts on the machine hosting the web server. The resources to which these
accounts have access must also be closely monitored and controlled. The vSphere
UI files must be adequately protected with correct permissions as applied out
of the box.


  "
  desc  'rationale', ''
  desc  'check', "
    At the command prompt, execute the following command:

    # find /usr/lib/vmware-vsphere-ui/server/lib
/usr/lib/vmware-vsphere-ui/server/conf -xdev -type f -a '(' -perm -o+w -o -not
-user vsphere-ui -o -not -group root ')' -exec ls -ld {} \\;

    If the command produces any output, this is a finding.
  "
  desc 'fix', "
    At the command prompt, execute the following command:

    # chmod o-w <file>
    # chown vsphere-ui:root <file>

    Repeat the command for each file that was returned.
  "
  impact 0.5
  tag severity: 'medium'
  tag gtitle: 'SRG-APP-000211-WSR-000030'
  tag satisfies: ['SRG-APP-000211-WSR-000030', 'SRG-APP-000380-WSR-000072']
  tag gid: 'V-239697'
  tag rid: 'SV-239697r679197_rule'
  tag stig_id: 'VCUI-67-000016'
  tag fix_id: 'F-42889r679196_fix'
  tag cci: ['CCI-001082', 'CCI-001813']
  tag nist: ['SC-2', 'CM-5 (1)']

  describe command("find '#{input('rootPath')}' /usr/lib/vmware-vsphere-ui/server/conf -xdev -type f -a \'(\' -perm -o+w -o -not -user vsphere-ui -o -not -group root \')\' -exec ls -ld {} \;") do
    its('stdout.strip') { should eq '' }
  end
end
