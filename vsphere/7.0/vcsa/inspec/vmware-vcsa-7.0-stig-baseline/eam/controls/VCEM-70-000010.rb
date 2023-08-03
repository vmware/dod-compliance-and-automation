control 'VCEM-70-000010' do
  title 'ESX Agent Manager must not be configured with unsupported realms.'
  desc 'ESX Agent Manager performs authentication at the application level and not through Tomcat. To eliminate unnecessary features and ensure ESX Agent Manager remains in its shipping state, the lack of a "UserDatabaseRealm" configuration must be confirmed.'
  desc 'check', 'At the command prompt, run the following command:

# grep UserDatabaseRealm /usr/lib/vmware-eam/web/conf/server.xml

If the command produces any output, this is a finding.'
  desc 'fix', 'Navigate to and open:

/usr/lib/vmware-eam/web/conf/server.xml

Remove the <Realm> node returned in the check.

Restart the service with the following command:

# vmon-cli --restart eam'
  impact 0.5
  tag check_id: 'C-60357r888600_chk'
  tag severity: 'medium'
  tag gid: 'V-256682'
  tag rid: 'SV-256682r888602_rule'
  tag stig_id: 'VCEM-70-000010'
  tag gtitle: 'SRG-APP-000141-WSR-000015'
  tag fix_id: 'F-60300r888601_fix'
  tag cci: ['CCI-000381']
  tag nist: ['CM-7 a']

  describe command("grep UserDatabaseRealm '#{input('serverXmlPath')}'") do
    its('stdout.strip') { should eq '' }
  end
end
