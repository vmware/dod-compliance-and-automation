control 'VCLU-70-000020' do
  title 'Lookup Service must set URIEncoding to UTF-8.'
  desc %q(Invalid user input occurs when a user inserts data or characters into a hosted application's data entry field and the hosted application is unprepared to process that data. This results in unanticipated application behavior, potentially leading to an application compromise. Invalid user input is one of the primary methods employed when attempting to compromise an application.

An attacker can also enter Unicode characters into hosted applications in an effort to break out of the document home or root home directory or to bypass security checks. Lookup Service must be configured to use a consistent character set via the "URIEncoding" attribute on the Connector nodes.)
  desc 'check', %q(At the command prompt, run the following command:

# xmllint --xpath '/Server/Service/Connector[@port="${bio-custom.http.port}"]/@URIEncoding' /usr/lib/vmware-lookupsvc/conf/server.xml

Expected result:

URIEncoding="UTF-8"

If the output does not match the expected result, this is a finding.)
  desc 'fix', %q(Navigate to and open:

/usr/lib/vmware-lookupsvc/conf/server.xml

Navigate to each of the <Connector> nodes.

Configure each <Connector> node with the value 'URIEncoding="UTF-8"'.

Restart the service with the following command:

# vmon-cli --restart lookupsvc)
  impact 0.5
  tag check_id: 'C-60400r888764_chk'
  tag severity: 'medium'
  tag gid: 'V-256725'
  tag rid: 'SV-256725r888766_rule'
  tag stig_id: 'VCLU-70-000020'
  tag gtitle: 'SRG-APP-000251-WSR-000157'
  tag fix_id: 'F-60343r888765_fix'
  tag cci: ['CCI-001310']
  tag nist: ['SI-10']

  describe xml("#{input('serverXmlPath')}") do
    its(['Server/Service/Connector[@port="${bio-custom.http.port}"]/@URIEncoding']) { should cmp "#{input('uriEncoding')}" }
  end
end
