control 'VCLU-70-000003' do
  title 'Lookup Service must limit the maximum size of a POST request.'
  desc 'The "maxPostSize" value is the maximum size in bytes of the POST that will be handled by the container FORM URL parameter parsing. Limit its size to reduce exposure to a denial-of-service attack.

If "maxPostSize" is not set, the default value of 2097152 (2MB) is used. Lookup Service is configured in its shipping state to not set a value for "maxPostSize".'
  desc 'check', %q(At the command prompt, run the following command:

# xmllint --xpath '/Server/Service/Connector[@port="${bio-custom.http.port}"]/@maxPostSize' /usr/lib/vmware-lookupsvc/conf/server.xml

Expected result:

XPath set is empty

If the output does not match the expected result, this is a finding.)
  desc 'fix', 'Navigate to and open:

/usr/lib/vmware-lookupsvc/conf/server.xml

In the <Connector> node, remove the "maxPostSize" key/value pair.

Restart the service with the following command:

# vmon-cli --restart lookupsvc'
  impact 0.5
  tag check_id: 'C-60383r888713_chk'
  tag severity: 'medium'
  tag gid: 'V-256708'
  tag rid: 'SV-256708r888715_rule'
  tag stig_id: 'VCLU-70-000003'
  tag gtitle: 'SRG-APP-000001-WSR-000001'
  tag fix_id: 'F-60326r888714_fix'
  tag cci: ['CCI-000054']
  tag nist: ['AC-10']

  describe xml("#{input('serverXmlPath')}") do
    its(['/Server/Service/Connector[@port="${bio-custom.http.port}"]/@maxPostSize']) { should cmp [] }
  end
end
