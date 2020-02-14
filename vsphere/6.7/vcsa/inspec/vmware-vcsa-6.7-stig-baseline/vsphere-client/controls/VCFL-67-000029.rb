control "VCFL-67-000029" do
  title "vSphere Client must disable the shutdown port."
  desc  "An attacker has at least two reasons to stop a web server. The first
is to cause a DoS, and the second is to put in place changes the attacker made
to the web server configuration. If the Tomcat shutdown port feature is
enabled, a shutdown signal can be sent to vSphere Client through this port. To
ensure availability, the shutdown port must be disabled."
  impact 0.5
  tag severity: "CAT II"
  tag gtitle: "SRG-APP-000435-WSR-000147"
  tag gid: nil
  tag rid: "VCFL-67-000029"
  tag stig_id: "VCFL-67-000029"
  tag cci: "CCI-002385"
  tag nist: ["SC-5", "Rev_4"]
  desc 'check', "# xmllint --format --xpath '/Server/@port'
/usr/lib/vmware-vsphere-client/server/configuration/tomcat-server.xml

Expected result:

port=\"-1\"

If the output does not match the expected result, this is a finding."
  desc 'fix', "Navigate to and open
/usr/lib/vmware-vsphere-client/server/configuration/tomcat-server.xml
in a text editor.

Make sure that the server port is disabled as follows:

<Server port=\"-1\">"

  describe xml('/usr/lib/vmware-vsphere-client/server/configuration/tomcat-server.xml') do
    its('Server/attribute::port') { should cmp '-1' }
  end

end