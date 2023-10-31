control 'WOAT-3X-000064' do
  title 'Workspace ONE Access must limit the number of allowed connections.'
  desc  'Limiting the number of established connections to the Workspace ONE Access is a basic DoS protection. Servers where the limit is too high or unlimited can potentially run out of system resources and negatively affect system availability.'
  desc  'rationale', ''
  desc  'check', "
    At the command prompt, execute the following command:

    # xmllint --xpath '/Server/Service/Connector/@port | /Server/Service/Connector/@acceptCount' /opt/vmware/horizon/workspace/conf/server.xml|sed 's/^ *//'

    Expected result:

    acceptCount=\"400\"
    port=\"${nio-ssl.https.port}\"
    acceptCount=\"100\"
    port=\"${http.port}\"
    acceptCount=\"400\"
    port=\"8443\"
    acceptCount=\"400\"
    port=\"${https.passthrough.port}\"

    If the output does not show an \"acceptCount\" of \"400\" for each port, this is a finding.
  "
  desc 'fix', "
    Navigate to and open:

    /opt/vmware/horizon/workspace/conf/server.xml

    Configure the <Connector> node with the corresponding acceptCount value:

    port=\"${nio-ssl.https.port}\" -> acceptCount=\"400\"

    port=\"${http.port}\" -> acceptCount=\"100\"

    port=\"8443\" -> acceptCount=\"400\"

    port=\"${https.passthrough.port}\" -> acceptCount=\"400\"
  "
  impact 0.5
  tag severity: 'medium'
  tag gtitle: 'SRG-APP-000246-WSR-000149'
  tag gid: 'V-WOAT-3X-000064'
  tag rid: 'SV-WOAT-3X-000064'
  tag stig_id: 'WOAT-3X-000064'
  tag cci: ['CCI-001094']
  tag nist: ['SC-5 (1)']

  describe xml("#{input('serverXmlPath')}") do
    its(['/Server/Service/Connector[@port="${nio-ssl.https.port}"]/@acceptCount']) { should cmp '400' }
  end

  describe xml("#{input('serverXmlPath')}") do
    its(['/Server/Service/Connector[@port="${http.port}"]/@acceptCount']) { should cmp '100' }
  end

  describe xml("#{input('serverXmlPath')}") do
    its(['/Server/Service/Connector[@port="8443"]/@acceptCount']) { should cmp '400' }
  end

  describe xml("#{input('serverXmlPath')}") do
    its(['/Server/Service/Connector[@port="${https.passthrough.port}"]/@acceptCount']) { should cmp '400' }
  end
end
