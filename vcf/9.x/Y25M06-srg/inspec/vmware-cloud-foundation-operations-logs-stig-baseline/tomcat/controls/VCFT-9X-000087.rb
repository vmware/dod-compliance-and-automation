control 'VCFT-9X-000087' do
  title 'The VMware Cloud Foundation Operations for Logs Loginsight service files must enforce access restrictions associated with changes to application server configuration.'
  desc  'As a rule, accounts on a web server are to be kept to a minimum. Only administrators, web managers, developers, auditors, and web authors require accounts on the machine hosting the web server. The resources to which these accounts have access must also be closely monitored and controlled.'
  desc  'rationale', ''
  desc  'check', "
    At the command prompt, run the following:

    # find /usr/lib/loginsight/application/3rd_party/apache-tomcat -xdev -type f -a '(' -perm -o+w -o -not -user root -o -not -group root ')' -exec ls -ld {} \\;

    If any files are returned, this is a finding.
  "
  desc 'fix', "
    At the command prompt, run the following:

    # chmod o-w <file>
    # chown root:root <file>

    Note: Substitute <file> with the listed file.
  "
  impact 0.5
  tag severity: 'medium'
  tag gtitle: 'SRG-APP-000380-AS-000088'
  tag gid: 'V-VCFT-9X-000087'
  tag rid: 'SV-VCFT-9X-000087'
  tag stig_id: 'VCFT-9X-000087'
  tag cci: ['CCI-001813']
  tag nist: ['CM-5 (1) (a)']

  describe command('find /usr/lib/loginsight/application/3rd_party/apache-tomcat -xdev -type f -a \'(\' -perm -o+w -o -not -user root -o -not -group root \')\' -exec ls -ld {} \\;') do
    its('stdout.strip') { should cmp '' }
  end
end
