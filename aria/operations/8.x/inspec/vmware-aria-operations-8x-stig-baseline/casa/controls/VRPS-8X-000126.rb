control 'VRPS-8X-000126' do
  title 'The Casa service must limit the number of times that each Transmission Control Protocol (TCP) connection is kept alive.'
  desc  "
    KeepAlive provides long lived HTTP sessions that allow multiple requests to be sent over the same connection. Enabling KeepAlive mitigates the effects of several types of denial-of-service attacks.

    An advantage of KeepAlive is the reduced latency in subsequent requests (no handshaking). However, a disadvantage is that server resources are not available to handle other requests while a connection is maintained between the server and the client.

    Tomcat can be configured to limit the number of subsequent requests that one client can submit to the server over an established connection. This limit helps provide a balance between the advantages of KeepAlive, while not allowing any one connection being held too long by any one client.
  "
  desc  'rationale', ''
  desc  'check', "
    The connection timeout should not be unlimited by setting it to \"-1\".

    At the command prompt, run the following command:

    # xmllint --xpath \"//Connector[@maxKeepAliveRequests = '-1']\" $CATALINA_BASE/conf/server.xml

    Expected result:

    XPath set is empty

    If any connectors are returned, this is a finding.
  "
  desc 'fix', "
    Navigate to and open:

    $CATALINA_BASE/conf/server.xml

    Configure the <Connector> node with the value:

    maxKeepAliveRequests=\"50\"

    Restart the service with the following command:

    # systemctl restart vmware-casa.service
  "
  impact 0.5
  tag severity: 'medium'
  tag gtitle: 'SRG-APP-000001-AS-000001'
  tag gid: 'V-VRPS-8X-000126'
  tag rid: 'SV-VRPS-8X-000126'
  tag stig_id: 'VRPS-8X-000126'
  tag cci: ['CCI-000054']
  tag nist: ['AC-10']

  # Open server.xml file
  xmlconf = xml(input('casa-serverXmlPath'))

  # maxKeepAliveRequests either shouldn't be present, or if it is, it should be not be -1
  describe xmlconf do
    its(["//Connector[@maxKeepAliveRequests = '-1']/@port"]) { should cmp [] }
  end
end
