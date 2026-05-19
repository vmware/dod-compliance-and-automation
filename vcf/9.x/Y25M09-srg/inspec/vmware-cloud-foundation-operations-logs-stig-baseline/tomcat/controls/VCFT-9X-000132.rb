control 'VCFT-9X-000132' do
  title 'The VMware Cloud Foundation Operations for Logs Loginsight service must limit the number of times that each TCP connection is kept alive.'
  desc  "
    KeepAlive provides long lived HTTP sessions that allow multiple requests to be sent over the same connection. Enabling KeepAlive mitigates the effects of several types of denial-of-service attacks.

    An advantage of KeepAlive is the reduced latency in subsequent requests (no handshaking). However, a disadvantage is that server resources are not available to handle other requests while a connection is maintained between the server and the client.

    Apache Tomcat can be configured to limit the number of subsequent requests that one client can submit to the server over an established connection. This limit helps provide a balance between the advantages of KeepAlive, while not allowing any one connection to be held too long by any one client.
  "
  desc  'rationale', ''
  desc  'check', "
    The maximum keep alive requests should not be disabled by setting it to \"-1\".

    At the command prompt, run the following:

    # xmllint --xpath \"//Connector[@maxKeepAliveRequests = '-1']\" /usr/lib/loginsight/application/3rd_party/apache-tomcat/conf/server.xml

    Example result:

    XPath set is empty

    If any connectors are returned, this is a finding.

    Note: If not specified the default value is 100.
  "
  desc 'fix', "
    Navigate to and open:

    /usr/lib/loginsight/application/etc/3rd_config/server.xml

    Configure the <Connector> node with the value:

    maxKeepAliveRequests=\"50\"

    Restart the service with the following command:

    # systemctl restart loginsight.service

    Note: The configuration in \"/usr/lib/loginsight/application/3rd_party/apache-tomcat/conf/server.xml\" is generated when the service restarts based on the contents of the \"/usr/lib/loginsight/application/etc/3rd_config/server.xml\" file.
  "
  impact 0.5
  tag severity: 'medium'
  tag gtitle: 'SRG-APP-000001-AS-000001'
  tag gid: 'V-VCFT-9X-000132'
  tag rid: 'SV-VCFT-9X-000132'
  tag stig_id: 'VCFT-9X-000132'
  tag cci: ['CCI-000054']
  tag nist: ['AC-10']

  # Open server.xml file and get the input variable value
  xmlconf = xml("#{input('catalinaBase')}/conf/server.xml")

  # maxKeepAliveRequests either shouldn't be present, or if it is, it should be not be -1
  describe xmlconf do
    its(["//Connector[@maxKeepAliveRequests = '-1']/@port"]) { should cmp [] }
  end
end
