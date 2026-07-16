control 'VCFT-9X-000131' do
  title 'The VMware Cloud Foundation Operations for Logs Loginsight service must limit the amount of time that each TCP connection is kept alive.'
  desc  "
    Denial of service (DoS) is one threat against web servers. Many DoS attacks attempt to consume web server resources in such a way that no more resources are available to satisfy legitimate requests.

    In Apache Tomcat, the \"connectionTimeout\" attribute sets the number of milliseconds the server will wait after accepting a connection for the request Uniform Resource Identifier (URI) line to be presented. This timeout will also be used when reading the request body (if any). This prevents idle sockets that are not sending HTTP requests from consuming system resources and potentially denying new connections.
  "
  desc  'rationale', ''
  desc  'check', "
    The connection timeout should not be disabled by setting it to \"-1\".

    At the command prompt, run the following:

    # xmllint --xpath \"//Connector[@connectionTimeout = '-1']\" /usr/lib/loginsight/application/3rd_party/apache-tomcat/conf/server.xml

    Example result:

    XPath set is empty

    If any connectors are returned, this is a finding.

    Note: If not specified the default value is 60000.
  "
  desc 'fix', "
    Navigate to and open:

    /usr/lib/loginsight/application/etc/3rd_config/server.xml

    Configure the <Connector> node with the value:

    connectionTimeout=\"20000\"

    Restart the service with the following command:

    # systemctl restart loginsight.service

    Note: The configuration in \"/usr/lib/loginsight/application/3rd_party/apache-tomcat/conf/server.xml\" is generated when the service restarts based on the contents of the \"/usr/lib/loginsight/application/etc/3rd_config/server.xml\" file.
  "
  impact 0.5
  tag severity: 'medium'
  tag gtitle: 'SRG-APP-000001-AS-000001'
  tag gid: 'V-VCFT-9X-000131'
  tag rid: 'SV-VCFT-9X-000131'
  tag stig_id: 'VCFT-9X-000131'
  tag cci: ['CCI-000054']
  tag nist: ['AC-10']

  # Open server.xml file and get the input variable value
  xmlconf = xml("#{input('catalinaBase')}/conf/server.xml")

  # connectionTimeout either shouldn't be present, or if it is, it should be not be -1
  describe xmlconf do
    its(["//Connector[@connectionTimeout = '-1']/@port"]) { should cmp [] }
  end
end
