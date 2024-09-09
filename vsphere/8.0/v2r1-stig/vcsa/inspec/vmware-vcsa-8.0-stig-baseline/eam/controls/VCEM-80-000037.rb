control 'VCEM-80-000037' do
  title 'The vCenter ESX Agent Manager service must be configured to use a specified IP address and port.'
  desc 'The server must be configured to listen on a specified IP address and port. Without specifying an IP address and port for server to use, the server will listen on all IP addresses available.

Accessing the hosted application through an IP address normally used for nonapplication functions opens the possibility of user access to resources, utilities, files, ports, and protocols that are protected on the desired application IP address.'
  desc 'check', %q(At the command prompt, run the following command:

# xmllint --xpath "//Connector[(@port = '0') or not(@address)]" /usr/lib/vmware-eam/web/conf/server.xml

Expected result:

XPath set is empty

If any connectors are returned, this is a finding.)
  desc 'fix', 'Navigate to and open:

/usr/lib/vmware-eam/web/conf/server.xml

Navigate to the <Connector> node and configure the port and address as follows:

port="${bio.http.port}"
address="localhost"

Restart the service with the following command:

# vmon-cli --restart eam'
  impact 0.5
  tag check_id: 'C-62750r934686_chk'
  tag severity: 'medium'
  tag gid: 'V-259010'
  tag rid: 'SV-259010r960966_rule'
  tag stig_id: 'VCEM-80-000037'
  tag gtitle: 'SRG-APP-000142-AS-000014'
  tag fix_id: 'F-62659r934687_fix'
  tag cci: ['CCI-000382']
  tag nist: ['CM-7 b']

  # Open server.xml file
  xmlconf = xml(input('serverXmlPath'))

  # Get a count of connectors without an 'address' attribute or where port equals 0
  describe xmlconf do
    its(["//Connector[(@port = '0') or not(@address)]/@port"]) { should cmp [] }
  end
end
