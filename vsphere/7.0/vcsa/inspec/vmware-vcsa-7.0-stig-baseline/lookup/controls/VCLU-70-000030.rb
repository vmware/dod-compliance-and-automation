# encoding: UTF-8

control 'VCLU-70-000030' do
  title 'Lookup Service must disable the shutdown port.'
  desc  "An attacker has at least two reasons to stop a web server. The first
is to cause a DoS, and the second is to put in place changes the attacker made
to the web server configuration. If the Tomcat shutdown port feature is
enabled, a shutdown signal can be sent to Lookup Service through this port. To
ensure availability, the shutdown port must be disabled.

  "
  desc  'rationale', ''
  desc  'check', "
    At the command prompt, execute the following commands:

    # xmllint --xpath '/Server/@port' /usr/lib/vmware-lookupsvc/conf/server.xml

    Expected result:

    port=\"${base.shutdown.port}\"

    If the output does not match the expected result, this is a finding.
  "
  desc  'fix', "
    Navigate to and open /usr/lib/vmware-lookupsvc/conf/server.xml

    Make sure that the server port is set as follows:

    <Server port=\"${base.shutdown.port}\">
  "
  impact 0.5
  tag severity: 'medium'
  tag gtitle: 'SRG-APP-000435-WSR-000147'
  tag gid: nil
  tag rid: nil
  tag stig_id: 'VCLU-70-000030'
  tag fix_id: nil
  tag cci: 'CCI-002385'
  tag nist: ['SC-5']

  describe xml("#{input('serverXmlPath')}") do
    its(['/Server/@port']) { should cmp "#{input('shutdownPortVariable')}" }
  end

end

