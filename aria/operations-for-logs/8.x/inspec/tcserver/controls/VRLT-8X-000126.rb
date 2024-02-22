control 'VRLT-8X-000126' do
  title 'The VMware Aria Operations for Logs tc Server must limit the number of times that each TCP connection is kept alive.'
  desc  "
    KeepAlive provides long lived HTTP sessions that allow multiple requests to be sent over the same connection. Enabling KeepAlive mitigates the effects of several types of denial-of-service attacks.

    An advantage of KeepAlive is the reduced latency in subsequent requests (no handshaking). However, a disadvantage is that server resources are not available to handle other requests while a connection is maintained between the server and the client.

    tc Server can be configured to limit the number of subsequent requests that one client can submit to the server over an established connection. This limit helps provide a balance between the advantages of KeepAlive, while not allowing any one connection being held too long by any one client. maxKeepAliveRequests is the tc Server attribute that sets this limit.

  "
  desc  'rationale', ''
  desc  'check', "
    At the command prompt, run the following command (replace maxKeepAliveRequests with appropriate value):

    #  xmllint --format --xpath \"//Connector[not(@maxKeepAliveRequests)] | //Connector[@maxKeepAliveRequests != '15']\" /usr/lib/loginsight/application/3rd_party/apache-tomcat/conf/server.xml | awk 1 RS='</Connector>' ORS='</Connector>\
    '

    For each connector node, if the value of \"maxKeepAliveRequests\" is not set to \"15\" or is missing, this is a finding.
  "
  desc 'fix', "
    Edit the /usr/lib/loginsight/application/etc/3rd_config/server.xml file.

    Navigate to each of the <Connector> nodes.

    Configure each <Connector> node with the value 'maxKeepAliveRequests=\"15\"'.

    Restart the service:
    # systemctl restart loginsight.service
  "
  impact 0.5
  tag severity: 'medium'
  tag gtitle: 'SRG-APP-000001-AS-000001'
  tag gid: 'V-VRLT-8X-000126'
  tag rid: 'SV-VRLT-8X-000126'
  tag stig_id: 'VRLT-8X-000126'
  tag cci: ['CCI-000054']
  tag nist: ['AC-10']

  # Open server.xml file
  xmlconf = xml("#{input('catalinaBase')}/conf/server.xml")
  mka = input('maxKeepAliveRequests')

  # Find connectors that are either missing the maxKeepAliveRequests value, or it is not set correctly
  describe xmlconf do
    its(["name(//Connector[not(@maxKeepAliveRequests)] | //Connector[@maxKeepAliveRequests != '#{mka}'])"]) { should cmp [] }
  end
end
