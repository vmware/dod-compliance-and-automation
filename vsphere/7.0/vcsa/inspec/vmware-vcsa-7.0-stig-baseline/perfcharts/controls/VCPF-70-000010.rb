control 'VCPF-70-000010' do
  title 'Performance Charts must not be configured with unsupported realms.'
  desc  'Performance Charts performs user authentication at the application level and not through Tomcat. Depending on the VCSA version, Performance Charts may come configured with a "UserDatabaseRealm". This should be removed as part of eliminating unnecessary features.'
  desc  'rationale', ''
  desc  'check', "
    At the command prompt, execute the following command:

    # grep UserDatabaseRealm /usr/lib/vmware-perfcharts/tc-instance/conf/server.xml

    If the command produces any output, this is a finding.
  "
  desc 'fix', "
    Navigate to and open:

    /usr/lib/vmware-perfcharts/tc-instance/conf/server.xml

    Remove the <Realm> node returned in the check.

    Restart the service with the following command:

    # vmon-cli --restart perfcharts
  "
  impact 0.5
  tag severity: 'medium'
  tag gtitle: 'SRG-APP-000141-WSR-000015'
  tag gid: nil
  tag rid: nil
  tag stig_id: 'VCPF-70-000010'
  tag cci: ['CCI-000381']
  tag nist: ['CM-7 a']

  describe command("grep UserDatabaseRealm '#{input('serverXmlPath')}'") do
    its('stdout.strip') { should eq '' }
  end
end
