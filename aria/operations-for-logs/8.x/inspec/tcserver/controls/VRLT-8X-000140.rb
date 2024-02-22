control 'VRLT-8X-000140' do
  title 'The VMware Aria Operations for Logs tc Server must disable the xpoweredBy attribute.'
  desc  'Individual connectors can be configured to display the tc Server info to clients. This information can be used to identify tc Server versions which can be useful to attackers for identifying vulnerable versions of tc Server. Individual connectors must be checked for the xpoweredBy attribute to ensure they do not pass server info to clients. The default value for xpoweredBy is false.'
  desc  'rationale', ''
  desc  'check', "
    At the command prompt, run the following command:

    # xmllint --xpath \"//Connector[@xpoweredBy]\" /usr/lib/loginsight/application/3rd_party/apache-tomcat/conf/server.xml

    If no results are returned, this is not a finding.

    If any connector elements contain xpoweredBy=\"true\", this is a finding.
  "
  desc 'fix', "
    Edit the /usr/lib/loginsight/application/etc/3rd_config/server.xml file.

    Examine each <Connector> element.

    Add or edit the xpoweredBy property to read xpoweredBy=\"false\".

    EXAMPLE:
    <Connector
      ...
      xpoweredBy=\"false\">
      ...
    </Connector>


    Restart the service:
    # systemctl restart loginsight.service
  "
  impact 0.5
  tag severity: 'medium'
  tag gtitle: 'SRG-APP-000141-AS-000095'
  tag gid: 'V-VRLT-8X-000140'
  tag rid: 'SV-VRLT-8X-000140'
  tag stig_id: 'VRLT-8X-000140'
  tag cci: ['CCI-000381']
  tag nist: ['CM-7 a']

  # Open server.xml file
  xmlconf = xml("#{input('catalinaBase')}/conf/server.xml")

  describe xmlconf do
    its(["name(//Connector[@xpoweredBy != 'false'])"]) { should cmp [] }
  end
end
