control 'TCSV-00-000037' do
  title 'tc Server must be configured to use a specified IP address and port.'
  desc  "
    The tc Server must be configured to listen on a specified IP address and port. Without specifying an IP address and port for the tc Server to utilize, the server will listen on all IP addresses available.

    Accessing the hosted application through an IP address normally used for non-application functions opens the possibility of user access to resources, utilities, files, ports, and protocols that are protected on the desired application IP address.
  "
  desc  'rationale', ''
  desc  'check', "
    At the command prompt, run the following command:

    # xmllint --xpath \"//Connector[not(@port) or not(@address)]\" $CATALINA_BASE/conf/server.xml

    If no values are returned, this is not a finding.

    If any values are returned, signifying either the IP address or the port is not specified for each <Connector>, this is a finding.
  "
  desc 'fix', "
    Edit the $CATALINA_HOME/server.xml file.

    Navigate to each of the <Connector> nodes.

    Configure each <Connector> node with the value 'address=\"XXXXX\"' and 'port=\"XXXX\"'.

    Note: Replace X values with the appropriate address and port for each connector.

    Restart the service:
    # systemctl restart loginsight.service
  "
  impact 0.5
  tag severity: 'medium'
  tag gtitle: 'SRG-APP-000142-AS-000014'
  tag satisfies: ['SRG-APP-000516-AS-000237']
  tag gid: 'V-TCSV-00-000037'
  tag rid: 'SV-TCSV-00-000037'
  tag stig_id: 'TCSV-00-000037'
  tag cci: %w(CCI-000366 CCI-000382)
  tag nist: ['CM-6 b', 'CM-7 b']

  # Open server.xml file
  xmlconf = xml("#{input('catalinaBase')}/conf/server.xml")

  # Get a count of connectors without an 'address' attribute
  describe xmlconf do
    its(['name(//Connector[not(@port) or not(@address)])']) { should cmp [] }
  end
end
