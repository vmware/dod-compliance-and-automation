control 'VCUI-70-000010' do
  title 'vSphere UI must not be configured with the UserDatabaseRealm enabled.'
  desc  "The vSphere UI performs user authentication at the application level and not through Tomcat. By default, there is no configuration for the UserDatabaseRealm Tomcat authentication mechanism. To eliminate unnecessary features and to ensure that the vSphere UI remains in it's shipping state, the lack of a UserDatabaseRealm configuration must be confirmed."
  desc  'rationale', ''
  desc  'check', "
    At the command prompt, execute the following command:

    # grep UserDatabaseRealm /usr/lib/vmware-vsphere-ui/server/conf/server.xml

    If the command produces any output, this is a finding.
  "
  desc 'fix', "
    Navigate to and open:

    /usr/lib/vmware-vsphere-ui/server/conf/server.xml

    Remove any and all <Realm> nodes.

    Restart the service with the following command:

    # vmon-cli --restart vsphere-ui
  "
  impact 0.5
  tag severity: 'medium'
  tag gtitle: 'SRG-APP-000141-WSR-000015'
  tag gid: nil
  tag rid: nil
  tag stig_id: 'VCUI-70-000010'
  tag cci: ['CCI-000381']
  tag nist: ['CM-7 a']

  describe command("grep UserDatabaseRealm '#{input('serverXmlPath')}'") do
    its('stdout.strip') { should eq '' }
  end
end
