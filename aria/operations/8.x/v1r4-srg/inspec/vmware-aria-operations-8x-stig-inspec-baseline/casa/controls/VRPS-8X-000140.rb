control 'VRPS-8X-000140' do
  title 'The VMware Aria Operations Casa service xpoweredBy attribute must be disabled.'
  desc  'Individual connectors can be configured to display the Tomcat information to clients. This information can be used to identify server versions that can be useful to attackers for identifying vulnerable versions of Tomcat. Individual connectors must be checked for the xpoweredBy attribute to ensure they do not pass server information to clients. The default value for xpoweredBy is "false".'
  desc  'rationale', ''
  desc  'check', "
    At the command prompt, run the following command:

    # xmllint --xpath \"//Connector/@xpoweredBy\" /usr/lib/vmware-casa/casa-webapp/conf/server.xml

    Example result:

    XPath set is empty

    If the \"xpoweredBy\" parameter is specified and is not \"false\", this is a finding.

    If the \"xpoweredBy\" parameter does not exist, this is not a finding.
  "
  desc 'fix', "
    Navigate to and open the /usr/lib/vmware-casa/casa-webapp/conf/server.xml file.

    Navigate to the <Connector> node and remove the \"xpoweredBy\" attribute.

    Restart the service with the following command:

    # systemctl restart vmware-casa.service
  "
  impact 0.5
  tag severity: 'medium'
  tag gtitle: 'SRG-APP-000141-AS-000095'
  tag gid: 'V-VRPS-8X-000140'
  tag rid: 'SV-VRPS-8X-000140'
  tag stig_id: 'VRPS-8X-000140'
  tag cci: ['CCI-000381']
  tag nist: ['CM-7 a']

  # Open server.xml file
  xmlconf = xml(input('casa-serverXmlPath'))

  describe xmlconf do
    its(["name(//Connector[@xpoweredBy != 'false'])"]) { should cmp [] }
  end
end
