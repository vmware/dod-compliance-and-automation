control 'VCPF-70-000010' do
  title 'Performance Charts must not be configured with unsupported realms.'
  desc 'Performance Charts performs user authentication at the application level and not through Tomcat. Depending on the vCenter Server Appliance (VCSA) version, Performance Charts may come configured with a "UserDatabaseRealm". This should be removed as part of eliminating unnecessary features.'
  desc 'check', 'At the command prompt, run the following command:

# grep UserDatabaseRealm /usr/lib/vmware-perfcharts/tc-instance/conf/server.xml

If the command produces any output, this is a finding.'
  desc 'fix', 'Navigate to and open:

/usr/lib/vmware-perfcharts/tc-instance/conf/server.xml

Remove the <Realm> node returned in the check.

Restart the service with the following command:

# vmon-cli --restart perfcharts'
  impact 0.5
  tag check_id: 'C-60295r888349_chk'
  tag severity: 'medium'
  tag gid: 'V-256620'
  tag rid: 'SV-256620r888351_rule'
  tag stig_id: 'VCPF-70-000010'
  tag gtitle: 'SRG-APP-000141-WSR-000015'
  tag fix_id: 'F-60238r888350_fix'
  tag cci: ['CCI-000381']
  tag nist: ['CM-7 a']

  describe command("grep UserDatabaseRealm '#{input('serverXmlPath')}'") do
    its('stdout.strip') { should eq '' }
  end
end
