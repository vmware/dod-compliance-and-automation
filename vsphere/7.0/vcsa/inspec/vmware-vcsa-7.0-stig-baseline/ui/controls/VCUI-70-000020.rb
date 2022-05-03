control 'VCUI-70-000020' do
  title 'vSphere UI must limit the number of allowed connections.'
  desc  'Limiting the number of established connections is a basic denial of service protection and a best practice. Servers where the limit is too high or unlimited can potentiall run out of system resources and negatively affect system availability.'
  desc  'rationale', ''
  desc  'check', "
    At the command prompt, execute the following command:

    # xmllint --xpath '/Server/Service/Connector[@port=\"${http.port}\"]/@acceptCount' /usr/lib/vmware-vsphere-ui/server/conf/server.xml

    Expected result:

    acceptCount=\"300\"

    If the output does not match the expected result, this is a finding.
  "
  desc 'fix', "
    Navigate to and open:

    /usr/lib/vmware-vsphere-ui/server/conf/server.xml

    Navigate to the <Connector> configured with port=\"${http.port}\".

    Add or change the folllowing value:

    acceptCount=\"300\"

    Restart the service with the following command:

    # vmon-cli --restart vsphere-ui
  "
  impact 0.5
  tag severity: 'medium'
  tag gtitle: 'SRG-APP-000246-WSR-000149'
  tag gid: nil
  tag rid: nil
  tag stig_id: 'VCUI-70-000020'
  tag cci: ['CCI-001094']
  tag nist: ['SC-5 (1)']

  describe xml("#{input('serverXmlPath')}") do
    its(['Server/Service/Connector/@acceptCount']) { should cmp "#{input('acceptCount')}" }
  end
end
