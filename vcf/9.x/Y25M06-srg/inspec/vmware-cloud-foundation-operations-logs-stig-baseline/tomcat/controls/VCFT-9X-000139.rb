control 'VCFT-9X-000139' do
  title 'The VMware Cloud Foundation Operations for Logs Loginsight service must disable the xpoweredBy parameter.'
  desc  'Individual connectors can be configured to display the tc Server info to clients. This information can be used to identify tc Server versions which can be useful to attackers for identifying vulnerable versions of Apache Tomcat. Individual connectors must be checked for the xpoweredBy attribute to ensure they do not pass server info to clients. The default value for xpoweredBy is false.'
  desc  'rationale', ''
  desc  'check', "
    At the command prompt, run the following:

    # xmllint --xpath \"//Connector/@xpoweredBy\" /usr/lib/loginsight/application/3rd_party/apache-tomcat/conf/server.xml

    Example result:

    XPath set is empty

    If the \"xpoweredBy\" parameter is specified and is not \"false\", this is a finding.

    If the \"xpoweredBy\" parameter does not exist, this is not a finding.
  "
  desc 'fix', "
    Navigate to and open:

    /usr/lib/loginsight/application/etc/3rd_config/server.xml

    Navigate to the <Connector> node and remove the \"xpoweredBy\" attribute.

    Restart the service with the following command:

    # systemctl restart loginsight.service

    Note: The configuration in \"/usr/lib/loginsight/application/3rd_party/apache-tomcat/conf/server.xml\" is generated when the service restarts based on the contents of the \"/usr/lib/loginsight/application/etc/3rd_config/server.xml\" file.
  "
  impact 0.5
  tag severity: 'medium'
  tag gtitle: 'SRG-APP-000516-AS-000237'
  tag gid: 'V-VCFT-9X-000139'
  tag rid: 'SV-VCFT-9X-000139'
  tag stig_id: 'VCFT-9X-000139'
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']

  # Open server.xml file
  xmlconf = xml("#{input('catalinaBase')}/conf/server.xml")

  describe xmlconf do
    its(["name(//Connector[@xpoweredBy != 'false'])"]) { should cmp [] }
  end
end
