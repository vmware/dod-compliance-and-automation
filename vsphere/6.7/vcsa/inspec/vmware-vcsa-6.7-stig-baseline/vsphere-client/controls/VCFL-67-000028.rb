control 'VCFL-67-000028' do
  title 'vSphere Client must be configured with the appropriate ports.'
  desc  "Web servers provide numerous processes, features, and functionalities
that use TCP/IP ports. Some of these processes may be deemed unnecessary or too
unsecure to run on a production system. vSphere Client comes configured with
two connectors. One is behind the reverse proxy and listening on 9090, and the
other is serving SSL natively on 9443. The ports that vSphere Client listens on
must be verified as accurate to their shipping state."
  desc  'rationale', ''
  desc  'check', "
    At the command prompt, execute the following command:

    # xmllint --format --xpath '/Server/Service/Connector/@port'
/usr/lib/vmware-vsphere-client/server/configuration/tomcat-server.xml

    Expected result:

    port=\"9090\" port=\"9443\"

    If the output does not match the expected result, this is a finding.
  "
  desc 'fix', "
    Navigate to and
open /usr/lib/vmware-vsphere-client/server/configuration/tomcat-server.xml in a
text editor.

    On the first <Connector>, with redirectPort=\"9443\", configure the port as
follows:

    port=\"9090\"

    On the second <Connector>, with SSLEnabled=\"true\", configure the port as
follows:

    port=\"9443\"
  "
  impact 0.5
  tag severity: 'medium'
  tag gtitle: 'SRG-APP-000383-WSR-000175'
  tag gid: 'V-239769'
  tag rid: 'SV-239769r679534_rule'
  tag stig_id: 'VCFL-67-000028'
  tag fix_id: 'F-42961r679533_fix'
  tag cci: ['CCI-001762']
  tag nist: ['CM-7 (1) (b)']

  describe xml('/usr/lib/vmware-vsphere-client/server/configuration/tomcat-server.xml') do
    its(['Server/Service/Connector[@redirectPort="9443"]/@port']) { should cmp '9090' }
  end

  describe xml('/usr/lib/vmware-vsphere-client/server/configuration/tomcat-server.xml') do
    its(['Server/Service/Connector[@SSLEnabled="true"]/@port']) { should cmp '9443' }
  end
end
