control "VCUI-67-000028" do
  title "vSphere UI must must be configured with the appropriate ports."
  desc  "Web servers provide numerous processes, features, and functionalities
that utilize TCP/IP ports. Some of these processes may be deemed unnecessary or
too unsecure to run on a production system. The ports that vSphere UI listens
on are configured in the catalina.properties file and must be veriified as
accurate to their shipping state."
  impact 0.5
  tag severity: "CAT II"
  tag gtitle: nil
  tag gid: nil
  tag rid: "VCUI-67-000028"
  tag stig_id: "VCUI-67-000028"
  tag cci: nil
  tag nist: nil
  desc 'check', "At the command prompt, execute the following command:

# grep '.port' /usr/lib/vmware-vsphere-ui/server/conf/catalina.properties

Expected result:

http.port=5090
proxy.port=443
https.port=5443

If the output of the command does not match the expected result, this is a
finding."
  desc 'fix', "Navigate to and open
/usr/lib/vmware-vsphere-ui/server/conf/catalina.properties

Navigate to the ports specification section.

Set the vSphere UI port specifications according to the shipping configuration
below:

http.port=5090
proxy.port=443
https.port=5443"

  describe parse_config_file('/usr/lib/vmware-vsphere-ui/server/conf/catalina.properties').params['http.port'] do
    it { should eq '5090' }
  end
  describe parse_config_file('/usr/lib/vmware-vsphere-ui/server/conf/catalina.properties').params['proxy.port'] do
    it { should eq '443' }
  end
  describe parse_config_file('/usr/lib/vmware-vsphere-ui/server/conf/catalina.properties').params['https.port'] do
    it { should eq '5443' }
  end

end