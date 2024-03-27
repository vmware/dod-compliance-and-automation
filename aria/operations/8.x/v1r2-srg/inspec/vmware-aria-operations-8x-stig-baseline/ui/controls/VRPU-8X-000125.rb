control 'VRPU-8X-000125' do
  title 'The UI service must limit the amount of time that each Transmission Control Protocol (TCP) connection is kept alive.'
  desc  "
    Denial of Service is one of many threats against web servers. Many DoS attacks attempt to consume web server resources in such a way that no more resources are available to satisfy legitimate requests.

    In Tomcat, the \"connectionTimeout\" attribute sets the number of milliseconds the server will wait after accepting a connection for the request Uniform Resource Identifier (URI) line to be presented. This timeout will also be used when reading the request body (if any). This prevents idle sockets that are not sending HTTP requests from consuming system resources and potentially denying new connections.
  "
  desc  'rationale', ''
  desc  'check', "
    The connection timeout should not be disabled by setting it to \"-1\".

    At the command prompt, run the following command:

    # xmllint --xpath \"//Connector[@connectionTimeout = '-1']\" $CATALINA_BASE/conf/server.xml

    Expected result:

    XPath set is empty

    If any connectors are returned, this is a finding.
  "
  desc 'fix', "
    Navigate to and open the $CATALINA_BASE/conf/server.xml file.

    Configure each<Connector> node with the value:

    connectionTimeout=\"60000\"

    Restart the service with the following command:

    # systemctl restart vmware-vcops-web.service
  "
  impact 0.5
  tag severity: 'medium'
  tag gtitle: 'SRG-APP-000001-AS-000001'
  tag gid: 'V-VRPU-8X-000125'
  tag rid: 'SV-VRPU-8X-000125'
  tag stig_id: 'VRPU-8X-000125'
  tag cci: ['CCI-000054']
  tag nist: ['AC-10']

  # Open server.xml file
  xmlconf = xml(input('ui-serverXmlPath'))

  # connectionTimeout either shouldn't be present, or if it is, it should be not be -1
  describe xmlconf do
    its(["//Connector[@connectionTimeout = '-1']/@port"]) { should cmp [] }
  end
end
