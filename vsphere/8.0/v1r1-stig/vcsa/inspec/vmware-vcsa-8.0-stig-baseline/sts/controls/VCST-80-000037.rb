control 'VCST-80-000037' do
  title 'The vCenter STS service must be configured to use a specified IP address and port.'
  desc 'The server must be configured to listen on a specified IP address and port. Without specifying an IP address and port for server to use, the server will listen on all IP addresses available.

Accessing the hosted application through an IP address normally used for nonapplication functions opens the possibility of user access to resources, utilities, files, ports, and protocols that are protected on the desired application IP address.'
  desc 'check', %q(At the command prompt, run the following command:

# xmllint --xpath '//Connector[not(@port = "${bio-ssl-clientauth.https.port}") and (@port = "0" or not(@address))]' /usr/lib/vmware-sso/vmware-sts/conf/server.xml

Expected result:

XPath set is empty

If any connectors are returned, this is a finding.)
  desc 'fix', 'Navigate to and open:

/usr/lib/vmware-sso/vmware-sts/conf/server.xml

The STS service has 2 connectors with the below pairs of ports and addresses.

Navigate to the target <Connector> node and configure the port and address as follows.

port="${bio-custom.http.port}"
address="localhost"

port="${bio-ssl-localhost.https.port}"
address="localhost"

Restart the service with the following command:

# vmon-cli --restart sts

Note: The connector with port="${bio-ssl-clientauth.https.port}" should not have address set.'
  impact 0.5
  tag check_id: 'C-62718r934590_chk'
  tag severity: 'medium'
  tag gid: 'V-258978'
  tag rid: 'SV-258978r934592_rule'
  tag stig_id: 'VCST-80-000037'
  tag gtitle: 'SRG-APP-000142-AS-000014'
  tag fix_id: 'F-62627r934591_fix'
  tag cci: ['CCI-000382']
  tag nist: ['CM-7 b']

  # Open server.xml file
  xmlconf = xml(input('serverXmlPath'))

  # Get a count of connectors without an 'address' attribute or where port equals 0
  describe xmlconf do
    its(['//Connector[not(@port = "${bio-ssl-clientauth.https.port}") and (@port = "0" or not(@address))]/@port']) { should cmp [] }
  end
end
