control 'VCST-80-000125' do
  title 'The vCenter STS service must limit the amount of time that each Transmission Control Protocol (TCP) connection is kept alive.'
  desc 'Denial of service (DoS) is one threat against web servers. Many DoS attacks attempt to consume web server resources in such a way that no more resources are available to satisfy legitimate requests.

In Tomcat, the "connectionTimeout" attribute sets the number of milliseconds the server will wait after accepting a connection for the request Uniform Resource Identifier (URI) line to be presented. This timeout will also be used when reading the request body (if any). This prevents idle sockets that are not sending HTTP requests from consuming system resources and potentially denying new connections.'
  desc 'check', %q(The connection timeout should not be disabled by setting it to "-1".

At the command prompt, run the following command:

# xmllint --xpath "//Connector[@connectionTimeout = '-1']" /usr/lib/vmware-sso/vmware-sts/conf/server.xml

Expected result:

XPath set is empty

If any connectors are returned, this is a finding.)
  desc 'fix', 'Navigate to and open:

/usr/lib/vmware-sso/vmware-sts/conf/server.xml

Configure the <Connector> node with the value:

connectionTimeout="60000"

Restart the service with the following command:

# vmon-cli --restart sts'
  impact 0.5
  tag check_id: 'C-62725r934611_chk'
  tag severity: 'medium'
  tag gid: 'V-258985'
  tag rid: 'SV-258985r934613_rule'
  tag stig_id: 'VCST-80-000125'
  tag gtitle: 'SRG-APP-000001-AS-000001'
  tag fix_id: 'F-62634r934612_fix'
  tag cci: ['CCI-000054']
  tag nist: ['AC-10']

  # Open server.xml file
  xmlconf = xml(input('serverXmlPath'))

  # connectionTimeout either shouldn't be present, or if it is, it should be not be -1
  describe xmlconf do
    its(["//Connector[@connectionTimeout = '-1']/@port"]) { should cmp [] }
  end
end
