control 'VRLT-8X-000125' do
  title 'The VMware Aria Operations for Logs tc Server must limit the amount of time that each TCP connection is kept alive.'
  desc  "
    Denial of Service is one of many threats against web servers. Many DoS attacks attempt to consume web server resources in such a way that no more resources are available to satisfy legitimate requests. Mitigation against these threats is to take steps to limit the number of resources that can be consumed in certain ways.

    tc Server provides the connectionTimeout attribute. This sets the number of milliseconds tc Server will wait, after accepting a connection, for the request URI line to be presented. This timeout will also be used when reading the request body (if any).
  "
  desc  'rationale', ''
  desc  'check', "
    At the command prompt, run the following command (substitute the appropriate connectionTimeout value):

    #  xmllint --format --xpath \"//Connector[not(@connectionTimeout)] | //Connector[@connectionTimeout != '20000']\" /usr/lib/loginsight/application/3rd_party/apache-tomcat/conf/server.xml | awk 1

    For each connector, if the value of \"connectionTimeout\" is not set to \"20000\" or is missing, this is a finding.
  "
  desc 'fix', "
    Edit the /usr/lib/loginsight/application/etc/3rd_config/server.xml file.

    Navigate to each of the <Connector> nodes.

    Configure each <Connector> node with the value 'connectionTimeout=\"20000\"'.

    EXAMPLE:
    <Connector
    ...
      connectionTimeout=\"20000\"
    ...>

    Restart the service:
    # systemctl restart loginsight.service
  "
  impact 0.5
  tag severity: 'medium'
  tag gtitle: 'SRG-APP-000001-AS-000001'
  tag gid: 'V-VRLT-8X-000125'
  tag rid: 'SV-VRLT-8X-000125'
  tag stig_id: 'VRLT-8X-000125'
  tag cci: ['CCI-000054']
  tag nist: ['AC-10']

  # Open server.xml file
  xmlconf = xml("#{input('catalinaBase')}/conf/server.xml")
  ct = input('connectionTimeout')

  # Find connectors that are either missing the connectionTimeout property, or it is not set to the allowed value
  describe xmlconf do
    its(["name(//Connector[not(@connectionTimeout)] | //Connector[@connectionTimeout != '#{ct}'])"]) { should cmp [] }
  end
end
