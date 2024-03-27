control 'WOAT-3X-000088' do
  title 'Workspace ONE Access must set the secure flag for cookies.'
  desc  'The secure flag is an option that can be set by the application server when sending a new cookie to the user within an HTTP Response. The purpose of the secure flag is to prevent cookies from being observed by unauthorized parties due to the transmission of a the cookie in clear text. By setting the secure flag, the browser will prevent the transmission of a cookie over an unencrypted channel. The horizon-workspace is configured to only be accessible over a TLS tunnel but this cookie flag is still a recommended best practice.'
  desc  'rationale', ''
  desc  'check', "
    At the command prompt, execute the following command:

    # xmllint --xpath '/Server/Service/Connector[@secure!=\"true\"]/@port' /opt/vmware/horizon/workspace/conf/server.xml|sed 's/^ *//'

    Expected result:

    XPath set is empty

    If the output does not match the expected result, this is a finding.
  "
  desc 'fix', "
    Navigate to and open:

    /opt/vmware/horizon/workspace/conf/server.xml

    Navigate to the connector node with the port returned in the check and configure it with secure=\"true\".

    Example:

    <Connector
                    URIEncoding=\"UTF-8\"
                    ...
                    secure=\"true\"
                    maxHttpHeaderSize=\"32768\">
    </Connector>
  "
  impact 0.5
  tag severity: 'medium'
  tag gtitle: 'SRG-APP-000380-WSR-000072'
  tag gid: 'V-WOAT-3X-000088'
  tag rid: 'SV-WOAT-3X-000088'
  tag stig_id: 'WOAT-3X-000088'
  tag cci: ['CCI-001813']
  tag nist: ['CM-5 (1)']

  begin
    xmlconf = xml("#{input('serverXmlPath')}")

    if xmlconf['Server/Service/Connector/attribute::secure'].is_a?(Array)
      xmlconf['Server/Service/Connector/attribute::secure'].each do |x|
        describe x do
          it { should cmp 'true' }
        end
      end
    else
      describe xml(xmlconf['Server/Service/Connector/attribute::secure']) do
        it { should cmp 'true' }
      end
    end
  end
end
