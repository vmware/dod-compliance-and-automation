control "VCST-67-000010" do
   title 'The Security Token Service must not be configured with unused realms.'
  desc  "The Security Token Service performs user authentication at the
application level and not through Tomcat. To eliminate unnecessary features and
ensure that the Security Token Service remains in its shipping state, the lack
of a \"UserDatabaseRealm\" configuration must be confirmed."
  desc  'rationale', ''
  desc  'check', "
    At the command prompt, execute the following command:

    # grep UserDatabaseRealm /usr/lib/vmware-sso/vmware-sts/conf/server.xml

    If the command produces any output, this is a finding.
  "
  desc  'fix', "
    Navigate to and open /usr/lib/vmware-sso/vmware-sts/conf/server.xml.

    Remove the <Realm> node returned in the check.
  "
  impact 0.5
  tag severity: 'medium'
  tag gtitle: 'SRG-APP-000141-WSR-000015'
  tag gid: 'V-239661'
  tag rid: 'SV-239661r679055_rule'
  tag stig_id: 'VCST-67-000010'
  tag fix_id: 'F-42853r679054_fix'
  tag cci: ['CCI-000381']
  tag nist: ['CM-7 a']

  describe command("grep UserDatabaseRealm '#{input('serverXmlPath')}'") do
    its ('stdout.strip') { should eq '' }
  end

end