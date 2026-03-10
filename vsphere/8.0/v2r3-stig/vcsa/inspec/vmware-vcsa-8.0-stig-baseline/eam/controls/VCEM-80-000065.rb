control 'VCEM-80-000065' do
  title 'The vCenter ESX Agent Manager service must set URIEncoding to UTF-8.'
  desc "Invalid user input occurs when a user inserts data or characters into a hosted application's data entry field and the hosted application is unprepared to process that data. This results in unanticipated application behavior, potentially leading to an application compromise. Invalid user input is one of the primary methods employed when attempting to compromise an application.

An attacker can also enter Unicode characters into hosted applications in an effort to break out of the document home or root home directory or bypass security checks."
  desc 'check', %q(At the command prompt, run the following command:

# xmllint --xpath "//Connector[@URIEncoding != 'UTF-8'] | //Connector[not[@URIEncoding]]" /usr/lib/vmware-eam/web/conf/server.xml

Expected result:

XPath set is empty

If any connectors are returned, this is a finding.)
  desc 'fix', 'Navigate to and open:

/usr/lib/vmware-eam/web/conf/server.xml

Configure the <Connector> node with the value:

URIEncoding="UTF-8"

Restart the service with the following command:

# vmon-cli --restart eam'
  impact 0.5
  tag check_id: 'C-62753r934695_chk'
  tag severity: 'medium'
  tag gid: 'V-259013'
  tag rid: 'SV-259013r961158_rule'
  tag stig_id: 'VCEM-80-000065'
  tag gtitle: 'SRG-APP-000251-AS-000165'
  tag fix_id: 'F-62662r934696_fix'
  tag cci: ['CCI-001310']
  tag nist: ['SI-10']

  # Open server.xml file
  xmlconf = xml(input('serverXmlPath'))

  # URIEncoding either shouldn't be present, or if it is, it should be UTF-8
  describe xmlconf do
    its(["//Connector[@URIEncoding != 'UTF-8']/@port"]) { should cmp [] }
  end
end
