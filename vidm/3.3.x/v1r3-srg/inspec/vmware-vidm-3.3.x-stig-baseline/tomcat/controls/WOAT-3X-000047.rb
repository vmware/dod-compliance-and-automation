control 'WOAT-3X-000047' do
  title 'Workspace ONE Access directory tree must have permissions in an "out of the box" state.'
  desc  'As a rule, accounts on a web server are to be kept to a minimum. Only administrators, web managers, developers, auditors, and web authors require accounts on the machine hosting the web server. The resources to which these accounts have access must also be closely monitored and controlled.'
  desc  'rationale', ''
  desc  'check', "
    At the command prompt, execute the following command:

    # find /opt/vmware/horizon/workspace/webapps/ -xdev -type f -a '(' -not -user horizon -o -not -group www ')' -exec ls -ld {} \\;

    If the command produces any output, this is a finding.
  "
  desc 'fix', "
    <html>At the command prompt, execute the following command:

    <i># </i>chown horizon:www <file_name>

    Repeat the command for each file that was returned

    Note: Replace <file_name> for the name of the file that was returned.</html>
  "
  impact 0.5
  tag severity: 'medium'
  tag gtitle: 'SRG-APP-000211-WSR-000030'
  tag gid: 'V-WOAT-3X-000047'
  tag rid: 'SV-WOAT-3X-000047'
  tag stig_id: 'WOAT-3X-000047'
  tag cci: ['CCI-001082']
  tag nist: ['SC-2']

  describe command("find /opt/vmware/horizon/workspace/webapps/ -xdev -type f -a '(' -not -user horizon -o -not -group www ')' -exec ls -ld {} \;") do
    its('stdout.strip') { should cmp '' }
  end
end
