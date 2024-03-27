control 'WOAT-3X-000065' do
  title 'Workspace ONE Access must set URIEncoding to UTF-8.'
  desc  "
    Invalid user input occurs when a user inserts data or characters into a hosted application's data entry field and the hosted application is unprepared to process that data. This results in unanticipated application behavior, potentially leading to an application compromise. Invalid user input is one of the primary methods employed when attempting to compromise an application.

    An attacker can also enter Unicode characters into hosted applications in an effort to break out of the document home or root home directory or to bypass security checks. Workspace ONE Access must be configured to use a consistent character set via the URIEncoding attribute on the Connector nodes.
  "
  desc  'rationale', ''
  desc  'check', "
    At the command prompt, execute the following command:

    # xmllint --xpath '/Server/Service/Connector/@port | /Server/Service/Connector/@URIEncoding' /opt/vmware/horizon/workspace/conf/server.xml|sed 's/^ *//'

    Expected result:

    URIEncoding=\"UTF-8\"
    port=\"${nio-ssl.https.port}\"
    URIEncoding=\"UTF-8\"
    port=\"${http.port}\"
    URIEncoding=\"UTF-8\"
    port=\"8443\"
    URIEncoding=\"UTF-8\"
    port=\"${https.passthrough.port}\"

    If the output does not match the expected result, this is a finding.
  "
  desc 'fix', "
    Navigate to and open:

    /opt/vmware/horizon/workspace/conf/server.xml

    Configure each <Connector> node with the value:

    URIEncoding=\"UTF-8\"
  "
  impact 0.5
  tag severity: 'medium'
  tag gtitle: 'SRG-APP-000251-WSR-000157'
  tag gid: 'V-WOAT-3X-000065'
  tag rid: 'SV-WOAT-3X-000065'
  tag stig_id: 'WOAT-3X-000065'
  tag cci: ['CCI-001310']
  tag nist: ['SI-10']

  begin
    xmlconf = xml("#{input('serverXmlPath')}")

    if xmlconf['Server/Service/Connector/attribute::URIEncoding'].is_a?(Array)
      xmlconf['Server/Service/Connector/attribute::URIEncoding'].each do |x|
        describe x do
          it { should eq "#{input('uriEncoding')}" }
        end
      end
    else
      describe xml(xmlconf['Server/Service/Connector/attribute::URIEncoding']) do
        it { should eq "#{input('uriEncoding')}" }
      end
    end
  end
end
