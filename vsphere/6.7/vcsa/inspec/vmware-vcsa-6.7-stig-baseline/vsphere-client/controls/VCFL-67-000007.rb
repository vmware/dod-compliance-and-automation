control "VCFL-67-000007" do
  title "vSphere Client must be configured to only communicate over TLS 1.2."
  desc  "Data exchanged between the user and the web server can range from
static display data to credentials used to log into the hosted application.
Even when data appears to be static, the non-displayed logic in a web page may
expose business logic or trusted system relationships. The integrity of all the
data being exchanged between the user and web server must always be trusted. To
protect the integrity and trust, encryption methods should be used to protect
the complete communication session.

    HTTP connections in Virgo are managed through the Connector object. The
vSphere Client endpoint has two Connectors. One is behind a reverse proxy which
terminates TLS and the other is serving TLS natively on 9443. We will be
addressing the first in a separate STIG while this control addresses ensuring
TLS is enabled on the 9443 Connector."
  impact 0.5
  tag severity: "CAT II"
  tag gtitle: "SRG-APP-000015-WSR-000014"
  tag gid: nil
  tag rid: "VCFL-67-000007"
  tag stig_id: "VCFL-67-000007"
  tag cci: "CCI-001453"
  tag nist: ["AC-17 (2)", "Rev_4"]
  desc 'check', "At the command prompt, execute the following command:

# xmllint --format --xpath
'/Server/Service/Connector[@port=9443]/SSLHostConfig/@protocols'
/usr/lib/vmware-vsphere-client/server/configuration/tomcat-server.xml

Expected result:

protocols=\"TLSv1.2\"

If the output does not match the expected result, this is a finding."
  desc 'fix', "Navigate to and open
/usr/lib/vmware-vsphere-client/server/configuration/tomcat-server.xml

Make sure that the <SSLHostConfig> node contains the following value:

protocols=\"TLSv1.2\"
"

  describe xml('/usr/lib/vmware-vsphere-client/server/configuration/tomcat-server.xml') do
    its(['Server/Service/Connector/SSLHostConfig/@protocols']) { should cmp 'TLSv1.2'}
  end

end