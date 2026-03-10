control 'VCST-70-000010' do
  title 'The Security Token Service must not be configured with unused realms.'
  desc 'The Security Token Service performs user authentication at the application level and not through Tomcat. To eliminate unnecessary features and ensure the Security Token Service remains in its shipping state, the lack of a "UserDatabaseRealm" configuration must be confirmed.'
  desc 'check', 'At the command prompt, run the following command:

# grep UserDatabaseRealm /usr/lib/vmware-sso/vmware-sts/conf/server.xml

If the command produces any output, this is a finding.'
  desc 'fix', 'Navigate to and open:

/usr/lib/vmware-sso/vmware-sts/conf/server.xml

Remove the <Realm> node returned in the check.

Restart the service with the following command:

# vmon-cli --restart sts'
  impact 0.5
  tag check_id: 'C-60429r889230_chk'
  tag severity: 'medium'
  tag gid: 'V-256754'
  tag rid: 'SV-256754r889232_rule'
  tag stig_id: 'VCST-70-000010'
  tag gtitle: 'SRG-APP-000141-WSR-000015'
  tag fix_id: 'F-60372r889231_fix'
  tag cci: ['CCI-000381']
  tag nist: ['CM-7 a']

  describe command("grep UserDatabaseRealm '#{input('serverXmlPath')}'") do
    its('stdout.strip') { should eq '' }
  end
end
