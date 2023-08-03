control 'VCST-70-000020' do
  title 'The Security Token Service must set "URIEncoding" to UTF-8.'
  desc %q(Invalid user input occurs when a user inserts data or characters into a hosted application's data entry field and the hosted application is unprepared to process that data. This results in unanticipated application behavior, potentially leading to an application compromise. Invalid user input is one of the primary methods employed when attempting to compromise an application.

An attacker can also enter Unicode characters into hosted applications in an effort to break out of the document home or root home directory or bypass security checks. The Security Token Service must be configured to use a consistent character set via the "URIEncoding" attribute on the Connector nodes.)
  desc 'check', %q(At the command prompt, run the following command:

# xmllint --xpath '/Server/Service/Connector[@port="${bio-custom.http.port}"]/@URIEncoding' /usr/lib/vmware-sso/vmware-sts/conf/server.xml

Expected result:

URIEncoding="UTF-8"

If the output does not match the expected result, this is a finding.)
  desc 'fix', %q(Navigate to and open:

/usr/lib/vmware-sso/vmware-sts/conf/server.xml

Navigate to each of the <Connector> nodes.

Configure each <Connector> node with the value 'URIEncoding="UTF-8"'.

Restart the service with the following command:

# vmon-cli --restart sts)
  impact 0.5
  tag check_id: 'C-60439r889260_chk'
  tag severity: 'medium'
  tag gid: 'V-256764'
  tag rid: 'SV-256764r889262_rule'
  tag stig_id: 'VCST-70-000020'
  tag gtitle: 'SRG-APP-000251-WSR-000157'
  tag fix_id: 'F-60382r889261_fix'
  tag cci: ['CCI-001310']
  tag nist: ['SI-10']

  describe xml("#{input('serverXmlPath')}") do
    its(['Server/Service/Connector[@port="${bio-custom.http.port}"]/@URIEncoding']) { should cmp "#{input('uriEncoding')}" }
  end
end
