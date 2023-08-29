control 'WOAT-3X-000006' do
  title 'Workspace ONE Access must use cryptography to protect the integrity of remote sessions.'
  desc  "
    Data exchanged between the user and the web server can range from static display data to credentials used to log into the hosted application. Even when data appears to be static, the non-displayed logic in a web page may expose business logic or trusted system relationships. The integrity of all the data being exchanged between the user and web server must always be trusted. To protect the integrity and trust, encryption methods should be used to protect the complete communication session.

    HTTP connections in TC Server are managed through the Connector object.  Setting the Connector's SSLEnabled flag, SSL handshake/encryption/decryption is enabled.
  "
  desc  'rationale', ''
  desc  'check', "
    At the command prompt, execute the following command:

    # xmllint --xpath '/Server/Service/Connector/@port | /Server/Service/Connector/@SSLEnabled' /opt/vmware/horizon/workspace/conf/server.xml|sed 's/^ *//'

    Expected result:

    SSLEnabled=\"true\"
    port=\"${nio-ssl.https.port}\"
    port=\"${http.port}\"
    SSLEnabled=\"true\"
    port=\"8443\"
    SSLEnabled=\"true\"
    port=\"${https.passthrough.port}\"

    If the output does not match the expected result to show that SSLEnabled=\"true\" for the listed ports, this is a finding.
  "
  desc 'fix', "
    Navigate to and open:

    /opt/vmware/horizon/workspace/conf/server.xml

    Configure each <Connector> node except the http redirector, 'port=\"${http.port}\"', with the value:

    SSLEnabled=\"true\"
  "
  impact 0.5
  tag severity: 'medium'
  tag gtitle: 'SRG-APP-000015-WSR-000014'
  tag satisfies: ['SRG-APP-000172-WSR-000104', 'SRG-APP-000315-WSR-000003', 'SRG-APP-000439-WSR-000152', 'SRG-APP-000439-WSR-000156', 'SRG-APP-000439-WSR-000188', 'SRG-APP-000441-WSR-000181', 'SRG-APP-000442-WSR-000182']
  tag gid: 'V-WOAT-3X-000006'
  tag rid: 'SV-WOAT-3X-000006'
  tag stig_id: 'WOAT-3X-000006'
  tag cci: ['CCI-000197', 'CCI-001453', 'CCI-002314', 'CCI-002418', 'CCI-002420', 'CCI-002422']
  tag nist: ['AC-17 (1)', 'AC-17 (2)', 'IA-5 (1) (c)', 'SC-8', 'SC-8 (2)']

  describe xml("#{input('serverXmlPath')}") do
    its(['/Server/Service/Connector[@port="${nio-ssl.https.port}"]/@SSLEnabled']) { should cmp 'true' }
  end

  describe xml("#{input('serverXmlPath')}") do
    its(['/Server/Service/Connector[@port="8443"]/@SSLEnabled']) { should cmp 'true' }
  end

  describe xml("#{input('serverXmlPath')}") do
    its(['/Server/Service/Connector[@port="${https.passthrough.port}"]/@SSLEnabled']) { should cmp 'true' }
  end
end
