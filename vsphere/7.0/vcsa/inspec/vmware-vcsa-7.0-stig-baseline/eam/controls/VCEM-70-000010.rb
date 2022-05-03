control 'VCEM-70-000010' do
  title 'ESX Agent Manager must not be configured with unsupported realms.'
  desc  "ESX Agent Manager performs authentication at the application level and not through Tomcat. To eliminate unnecessary features and to ensure that ESX Agent Manager remains in it's shipping state, the lack of a UserDatabaseRealm configuration must be confirmed."
  desc  'rationale', ''
  desc  'check', "
    At the command prompt, execute the following command:

    # grep UserDatabaseRealm /usr/lib/vmware-eam/web/conf/server.xml

    If the command produces any output, this is a finding.
  "
  desc 'fix', "
    Navigate to and open:

    /usr/lib/vmware-eam/web/conf/server.xml

    Remove the <Realm> node returned in the check.

    Restart the service with the following command:

    # vmon-cli --restart eam
  "
  impact 0.5
  tag severity: 'medium'
  tag gtitle: 'SRG-APP-000141-WSR-000015'
  tag gid: nil
  tag rid: nil
  tag stig_id: 'VCEM-70-000010'
  tag cci: ['CCI-000381']
  tag nist: ['CM-7 a']

  describe command("grep UserDatabaseRealm '#{input('serverXmlPath')}'") do
    its('stdout.strip') { should eq '' }
  end
end
