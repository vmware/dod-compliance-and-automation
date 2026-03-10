control 'VCLU-70-000010' do
  title 'Lookup Service must not be configured with the "UserDatabaseRealm" enabled.'
  desc 'The Lookup Service performs user authentication at the application level and not through Tomcat. By default, there is no configuration for the "UserDatabaseRealm" Tomcat authentication mechanism. As part of eliminating unnecessary features and to ensure the Lookup Service remains in its shipping state, the lack of a "UserDatabaseRealm" configuration must be confirmed.'
  desc 'check', 'At the command prompt, run the following command:

# grep UserDatabaseRealm /usr/lib/vmware-lookupsvc/conf/server.xml

If the command produces any output, this is a finding.'
  desc 'fix', 'Navigate to and open:

/usr/lib/vmware-lookupsvc/conf/server.xml

Remove all <Realm> nodes.

Restart the service with the following command:

# vmon-cli --restart lookupsvc'
  impact 0.5
  tag check_id: 'C-60390r888734_chk'
  tag severity: 'medium'
  tag gid: 'V-256715'
  tag rid: 'SV-256715r888736_rule'
  tag stig_id: 'VCLU-70-000010'
  tag gtitle: 'SRG-APP-000141-WSR-000015'
  tag fix_id: 'F-60333r888735_fix'
  tag cci: ['CCI-000381']
  tag nist: ['CM-7 a']

  describe command("grep UserDatabaseRealm '#{input('serverXmlPath')}'") do
    its('stdout.strip') { should eq '' }
  end
end
