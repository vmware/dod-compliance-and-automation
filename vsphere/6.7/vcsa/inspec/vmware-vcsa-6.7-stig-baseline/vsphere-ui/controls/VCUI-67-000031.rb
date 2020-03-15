control "VCUI-67-000031" do
  title "vSphere UI must not be configured with unsupported realms."
  desc  "vSphere UI performs user authentication at the
application level and not through Tomcat. In the name of eliminating
unnecessary features and to ensure that the vSphere UI remains in
it's shipping state, the lack of a UserDatabaseRealm configuration must be
confirmed."
  impact 0.5
  tag severity: "CAT II"
  tag gtitle: "SRG-APP-000141-WSR-000015"
  tag gid: nil
  tag rid: "VCUI-67-000031"
  tag stig_id: "VCUI-67-000031"
  tag cci: "CCI-000381"
  tag nist: ["CM-7 a", "Rev_4"]
  desc 'check', "At the command prompt, execute the following command:

# grep UserDatabaseRealm /usr/lib/vmware-vsphere-ui/server/conf/server.xml

If the command produces any output, this is a finding."
  desc 'fix', "Navigate to and open /usr/lib/vmware-vsphere-ui/server/conf/server.xml
. Remove the <Realm> node returned in the check."

  describe command('grep UserDatabaseRealm /usr/lib/vmware-vsphere-ui/server/conf/server.xml') do
    its ('stdout.strip') { should eq '' }
  end

end