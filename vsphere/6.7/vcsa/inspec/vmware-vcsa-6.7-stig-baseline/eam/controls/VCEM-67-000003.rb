control 'VCEM-67-000003' do
  title 'ESX Agent Manager must limit the maximum size of a POST request.'
  desc  "The \"maxPostSize\" value is the maximum size in bytes of the POST
that will be handled by the container FORM URL parameter parsing. Limit its
size to reduce exposure to a denial-of-service attack. If \"maxPostSize\" is
not set, the default value of 2097152 (2 MB) is used. ESX Agent Manager is
configured in its shipping state to not set a value for \"maxPostSize\"."
  desc  'rationale', ''
  desc  'check', "
    At the command prompt, execute the following command:

    # xmllint --xpath
'/Server/Service/Connector[@port=\"${bio-custom.http.port}\"]/@maxPostSize'
/usr/lib/vmware-eam/web/conf/server.xml

    Expected result:

    XPath set is empty

    If the output does not match the expected result, this is a finding.
  "
  desc 'fix', "
    Navigate to and open:

    /usr/lib/vmware-eam/web/conf/server.xml

    Remove any configuration for \"maxPostSize\" from the <Connector> node.
  "
  impact 0.5
  tag severity: 'medium'
  tag gtitle: 'SRG-APP-000001-WSR-000001'
  tag gid: 'V-239374'
  tag rid: 'SV-239374r674616_rule'
  tag stig_id: 'VCEM-67-000003'
  tag fix_id: 'F-42566r674615_fix'
  tag cci: ['CCI-000054']
  tag nist: ['AC-10']

  describe xml("#{input('serverXmlPath')}") do
    its('Server/Service/Connector/attribute::maxPostSize') { should eq [] }
  end
end
