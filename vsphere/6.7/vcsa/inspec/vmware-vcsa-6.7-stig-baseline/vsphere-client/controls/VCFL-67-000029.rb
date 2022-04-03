control 'VCFL-67-000029' do
  title 'vSphere Client must disable the shutdown port.'
  desc  "An attacker has at least two reasons to stop a web server. The first
is to cause a denial of service, and the second is to put in place changes the
attacker made to the web server configuration. If the Tomcat shutdown port
feature is enabled, a shutdown signal can be sent to vSphere Client through
this port. To ensure availability, the shutdown port must be disabled."
  desc  'rationale', ''
  desc  'check', "
    At the command prompt, execute the following command:

    # xmllint --format --xpath '/Server/@port'
/usr/lib/vmware-vsphere-client/server/configuration/tomcat-server.xml

    Expected result:

    port=\"-1\"

    If the output does not match the expected result, this is a finding.
  "
  desc 'fix', "
    Navigate to and
open /usr/lib/vmware-vsphere-client/server/configuration/tomcat-server.xml in a
text editor.

    Ensure that the server port is disabled as follows:

    <Server port=\"-1\">
  "
  impact 0.5
  tag severity: 'medium'
  tag gtitle: 'SRG-APP-000435-WSR-000147'
  tag gid: 'V-239770'
  tag rid: 'SV-239770r679537_rule'
  tag stig_id: 'VCFL-67-000029'
  tag fix_id: 'F-42962r679536_fix'
  tag cci: ['CCI-002385']
  tag nist: ['SC-5']

  describe xml('/usr/lib/vmware-vsphere-client/server/configuration/tomcat-server.xml') do
    its('Server/attribute::port') { should cmp '-1' }
  end
end
