control 'VCFL-67-000008' do
  title 'vSphere Client must be configured to use the HTTPS scheme.'
  desc  "Data exchanged between the user and the web server can range from
static display data to credentials used to log into the hosted application.
Even when data appears to be static, the non-displayed logic in a web page may
expose business logic or trusted system relationships. The integrity of all the
data being exchanged between the user and web server must always be trusted. To
protect the integrity and trust, encryption methods should be used to protect
the complete communication session.

    HTTP connections in Virgo are managed through the Connector object. The
vSphere Client endpoint has two connectors. One is behind a reverse proxy that
terminates TLS and the other is serving TLS natively on 9443. The first will be
addressed in a separate STIG, while this control addresses ensuring TLS is
enabled on the 9443 connector.
  "
  desc  'rationale', ''
  desc  'check', "
    At the command prompt, execute the following command:

    # xmllint --format --xpath '/Server/Service/Connector[@port=9443]/@scheme'
/usr/lib/vmware-vsphere-client/server/configuration/tomcat-server.xml

    Expected result:

    scheme=\"https\"

    If the output does not match the expected result, this is a finding.
  "
  desc 'fix', "
    Navigate to and open
/usr/lib/vmware-vsphere-client/server/configuration/tomcat-server.xml.

    Ensure that the <Connector> node with 'port=9443' contains the following
value:

    scheme=\"https\"
  "
  impact 0.5
  tag severity: 'medium'
  tag gtitle: 'SRG-APP-000015-WSR-000014'
  tag gid: 'V-239750'
  tag rid: 'SV-239750r679477_rule'
  tag stig_id: 'VCFL-67-000008'
  tag fix_id: 'F-42942r679476_fix'
  tag cci: ['CCI-001453']
  tag nist: ['AC-17 (2)']

  describe xml('/usr/lib/vmware-vsphere-client/server/configuration/tomcat-server.xml') do
    its(['Server/Service/Connector[@port="9443"]/@scheme']) { should cmp 'https' }
  end
end
