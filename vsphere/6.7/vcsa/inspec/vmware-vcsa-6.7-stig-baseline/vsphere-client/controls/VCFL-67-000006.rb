control 'VCFL-67-000006' do
  title 'vSphere Client must be configured to enable SSL/TLS.'
  desc  "Data exchanged between the user and the web server can range from
static display data to credentials used to log into the hosted application.
Even when data appears to be static, the non-displayed logic in a web page may
expose business logic or trusted system relationships. The integrity of all the
data being exchanged between the user and web server must always be trusted. To
protect the integrity and trust, encryption methods should be used to protect
the complete communication session.

    HTTP connections in Virgo are managed through the Connector object. The
vSphere Client endpoint has two connectors. One is behind a reverse proxy,
which terminates TLS, and the other is serving SSL/TLS natively on 9443. The
first will be addressed in a separate STIG, while this control addresses
ensuring SSL/TLS is enabled on the 9443 connector.
  "
  desc  'rationale', ''
  desc  'check', "
    At the command prompt, execute the following command:

    # xmllint --format --xpath
'/Server/Service/Connector[@port=9443]/@SSLEnabled'
/usr/lib/vmware-vsphere-client/server/configuration/tomcat-server.xml

    Expected result:

    SSLEnabled=\"true\"

    If the output does not match the expected result, this is a finding.
  "
  desc 'fix', "
    Navigate to and open
/usr/lib/vmware-vsphere-client/server/configuration/tomcat-server.xml.

    Ensure that the <Connector> node with 'port=9443' contains the following
value:

    SSLEnabled=\"true\"
  "
  impact 0.7
  tag severity: 'high'
  tag gtitle: 'SRG-APP-000015-WSR-000014'
  tag satisfies: ['SRG-APP-000015-WSR-000014', 'SRG-APP-000172-WSR-000104',
'SRG-APP-000315-WSR-000004', 'SRG-APP-000439-WSR-000151',
'SRG-APP-000439-WSR-000152', 'SRG-APP-000439-WSR-000156',
'SRG-APP-000442-WSR-000182']
  tag gid: 'V-239748'
  tag rid: 'SV-239748r679471_rule'
  tag stig_id: 'VCFL-67-000006'
  tag fix_id: 'F-42940r679470_fix'
  tag cci: ['CCI-000197', 'CCI-000803', 'CCI-001453', 'CCI-002314',
'CCI-002418', 'CCI-002422']
  tag nist: ['IA-5 (1) (c)', 'IA-7', 'AC-17 (2)', 'AC-17 (1)', 'SC-8', "SC-8
(2)"]

  describe xml('/usr/lib/vmware-vsphere-client/server/configuration/tomcat-server.xml') do
    its(['Server/Service/Connector[@port="9443"]/@SSLEnabled']) { should cmp 'true' }
  end
end
