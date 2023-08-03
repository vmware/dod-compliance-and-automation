control 'VCUI-70-000003' do
  title 'vSphere UI must limit the maximum size of a POST request.'
  desc 'The "maxPostSize" value is the maximum size in bytes of the POST which will be handled by the container FORM URL parameter parsing. Limit its size to reduce exposure to a denial-of-service attack.

If "maxPostSize" is not set, the default value of 2097152 (2MB) is used. The vSphere UI is configured in its shipping state to not set a value for "maxPostSize".'
  desc 'check', %q(At the command prompt, run the following command:

# xmllint --xpath '/Server/Service/Connector[@port="${http.port}"]/@maxPostSize' /usr/lib/vmware-vsphere-ui/server/conf/server.xml

Expected result:

XPath set is empty

If the output does not match the expected result, this is a finding.)
  desc 'fix', 'Navigate to and open:

/usr/lib/vmware-vsphere-ui/server/conf/server.xml

Navigate to each of the <Connector> nodes.

Remove any configuration for "maxPostSize".

Restart the service with the following command:

# vmon-cli --restart vsphere-ui'
  impact 0.5
  tag check_id: 'C-60455r889337_chk'
  tag severity: 'medium'
  tag gid: 'V-256780'
  tag rid: 'SV-256780r889339_rule'
  tag stig_id: 'VCUI-70-000003'
  tag gtitle: 'SRG-APP-000001-WSR-000001'
  tag fix_id: 'F-60398r889338_fix'
  tag cci: ['CCI-000054']
  tag nist: ['AC-10']

  describe xml("#{input('serverXmlPath')}") do
    its('Server/Service/Connector/attribute::maxPostSize') { should eq [] }
  end
end
