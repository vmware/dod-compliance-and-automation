control "VCFL-67-000006" do
  title "vSphere Client must be configured to enable SSL/TLS."
  desc  "Data exchanged between the user and the web server can range from
static display data to credentials used to log into the hosted application.
Even when data appears to be static, the non-displayed logic in a web page may
expose business logic or trusted system relationships. The integrity of all the
data being exchanged between the user and web server must always be trusted. To
protect the integrity and trust, encryption methods should be used to protect
the complete communication session.

    HTTP connections in Virgo are managed through the Connector object. The
vSphere Client endpoint has two connectors. One is behind a reverse proxy which
terminates TLS and the other is serving SSL/TLS natively on 9443. We will be
addressing the first in a separate STIG while this control addresses ensuring
SSL/TLS is enabled on the 9443 connector."
  impact 0.5
  tag severity: "CAT II"
  tag gtitle: "SRG-APP-000015-WSR-000014"
  tag gid: nil
  tag rid: "VCFL-67-000006"
  tag stig_id: "VCFL-67-000006"
  tag cci: "CCI-001453"
  tag nist: ["AC-17 (2)", "Rev_4"]
  desc 'check', "At the command prompt, execute the following command:

# xmllint --format --xpath '/Server/Service/Connector[@port=9443]/@SSLEnabled'
/usr/lib/vmware-vsphere-client/server/configuration/tomcat-server.xml

Expected result:

SSLEnabled=\"true\"

If the output does not match the expected result, this is a finding."
  desc 'fix', "Navigate to and open
/usr/lib/vmware-vsphere-client/server/configuration/tomcat-server.xml

Make sure that the <Connector> node with 'port=9443' contains the following
value:

SSLEnabled=\"true\"
"

  describe xml('/usr/lib/vmware-vsphere-client/server/configuration/tomcat-server.xml') do
    its(['Server/Service/Connector[@port="9443"]/@SSLEnabled']) { should cmp 'true'}
  end

end