control "VCUI-67-000029" do
  title "vSphere UI must disable the shutdown port."
  desc  "An attacker has at least two reasons to stop a web server. The first
is to cause a DoS, and the second is to put in place changes the attacker made
to the web server configuration. If the Tomcat shutdown port feature is
enabled, a shutdown signal can be sent to vSphere UI through this port. To
ensure availability, the shutdown port must be disabled."
  impact 0.5
  tag severity: "CAT II"
  tag gtitle: nil
  tag gid: nil
  tag rid: "VCUI-67-000029"
  tag stig_id: "VCUI-67-000029"
  tag cci: nil
  tag nist: nil
  desc 'check', "At the command prompt, execute the following commands:

# xmllint --format /usr/lib/vmware-vsphere-ui/server/conf/server.xml | sed '2
s/xmlns=\".*\"//g' |  xmllint --xpath '/Server/@port' -

Expected result:

port=\"${shutdown.port}\"

If the output does not match the expected result, this is a finding.

# grep shutdown /etc/vmware/vmware-vmon/svcCfgfiles/vsphere-ui.json

Expected result:

\"-Dshutdown.port=-1\",

If the output does not match the expected result, this is a finding."
  desc 'fix', "Navigate to and open
/usr/lib/vmware-vsphere-ui/server/conf/server.xml

Make sure that the server port is disabled:

<Server port=\"-1\""

  describe xml('/usr/lib/vmware-vsphere-ui/server/conf/server.xml') do
    its('Server/attribute::port') { should include '${shutdown.port}' }
  end

  describe json('/etc/vmware/vmware-vmon/svcCfgfiles/vsphere-ui.json') do
    its('StartCommandArgs') { should include '-Dshutdown.port=-1'}
  end

end