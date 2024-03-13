control 'VCLU-70-000030' do
  title 'Lookup Service must disable the shutdown port.'
  desc 'An attacker has at least two reasons to stop a web server. The first is to cause a denial of service, and the second is to put in place changes the attacker made to the web server configuration. If the Tomcat shutdown port feature is enabled, a shutdown signal can be sent to the Lookup Service through this port. To ensure availability, the shutdown port must be disabled.'
  desc 'check', %q(At the command prompt, run the following commands:

# xmllint --xpath '/Server/@port' /usr/lib/vmware-lookupsvc/conf/server.xml

Expected result:

port="${base.shutdown.port}"

If the output does not match the expected result, this is a finding.)
  desc 'fix', 'Navigate to and open:

/usr/lib/vmware-lookupsvc/conf/server.xml

Ensure the server port is set as follows:

<Server port="${base.shutdown.port}">

Restart the service with the following command:

# vmon-cli --restart lookupsvc'
  impact 0.5
  tag check_id: 'C-60410r888794_chk'
  tag severity: 'medium'
  tag gid: 'V-256735'
  tag rid: 'SV-256735r888796_rule'
  tag stig_id: 'VCLU-70-000030'
  tag gtitle: 'SRG-APP-000435-WSR-000147'
  tag fix_id: 'F-60353r888795_fix'
  tag cci: ['CCI-002385']
  tag nist: ['SC-5 a']

  describe xml("#{input('serverXmlPath')}") do
    its(['/Server/@port']) { should cmp "#{input('shutdownPortVariable')}" }
  end
end
