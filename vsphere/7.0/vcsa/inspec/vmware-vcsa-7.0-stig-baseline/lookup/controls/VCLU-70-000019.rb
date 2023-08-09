control 'VCLU-70-000019' do
  title 'Lookup Service must limit the number of allowed connections.'
  desc 'Limiting the number of established connections is a basic denial-of-service protection and a best practice. Servers where the limit is too high or unlimited could run out of system resources and negatively affect system availability.'
  desc 'check', %q(At the command prompt, run the following command:

# xmllint --xpath '/Server/Service/Connector[@port="${bio-custom.http.port}"]/@acceptCount' /usr/lib/vmware-lookupsvc/conf/server.xml

Expected result:

acceptCount="100"

If the output does not match the expected result, this is a finding.)
  desc 'fix', 'Navigate to and open:

/usr/lib/vmware-lookupsvc/conf/server.xml

Navigate to the <Connector> configured with port="${bio-custom.http.port}".

Add or change the following value:

acceptCount="100"

Restart the service with the following command:

# vmon-cli --restart lookupsvc'
  impact 0.5
  tag check_id: 'C-60399r888761_chk'
  tag severity: 'medium'
  tag gid: 'V-256724'
  tag rid: 'SV-256724r888763_rule'
  tag stig_id: 'VCLU-70-000019'
  tag gtitle: 'SRG-APP-000246-WSR-000149'
  tag fix_id: 'F-60342r888762_fix'
  tag cci: ['CCI-001094']
  tag nist: ['SC-5 (1)']

  describe xml("#{input('serverXmlPath')}") do
    its(['Server/Service/Connector/@acceptCount']) { should cmp "#{input('acceptCount')}" }
  end
end
