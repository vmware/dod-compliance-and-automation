control 'WOAT-3X-000027' do
  title 'Workspace ONE Access must not be configured with unsupported realms.'
  desc  "Workspace ONE Access performs authentication at the application level and not through Tomcat. In the name of eliminating unnecessary features and to ensure that Workspace ONE Access remains in it's shipping state, the lack of a UserDatabaseRealm configuration must be confirmed."
  desc  'rationale', ''
  desc  'check', "
    At the command prompt, execute the following command:

    # grep UserDatabaseRealm /opt/vmware/horizon/workspace/conf/server.xml

    If the command produces any output, this is a finding.
  "
  desc 'fix', "
    Navigate to and open:

    /opt/vmware/horizon/workspace/conf/server.xml

    Remove the <Realm> node returned in the check.
  "
  impact 0.5
  tag severity: 'medium'
  tag gtitle: 'SRG-APP-000141-WSR-000015'
  tag gid: 'V-WOAT-3X-000027'
  tag rid: 'SV-WOAT-3X-000027'
  tag stig_id: 'WOAT-3X-000027'
  tag cci: ['CCI-000381']
  tag nist: ['CM-7 a']

  describe command("grep UserDatabaseRealm '#{input('serverXmlPath')}'") do
    its('stdout.strip') { should cmp '' }
  end
end
