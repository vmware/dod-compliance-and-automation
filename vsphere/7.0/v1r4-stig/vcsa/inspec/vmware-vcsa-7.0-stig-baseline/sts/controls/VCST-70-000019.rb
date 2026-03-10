control 'VCST-70-000019' do
  title 'The Security Token Service must limit the number of allowed connections.'
  desc 'Limiting the number of established connections to the Security Token Service is a basic denial-of-service protection. Servers where the limit is too high or unlimited can potentially run out of system resources and negatively affect system availability.'
  desc 'check', %q(At the command prompt, run the following command:

# xmllint --xpath '/Server/Service/Connector[@port="${bio-custom.http.port}"]/@acceptCount' /usr/lib/vmware-sso/vmware-sts/conf/server.xml

Expected result:

acceptCount="100"

If the output does not match the expected result, this is a finding.)
  desc 'fix', 'Navigate to and open:

/usr/lib/vmware-sso/vmware-sts/conf/server.xml

Navigate to the <Connector> configured with port="${bio-custom.http.port}".

Add or change the following value:

acceptCount="100"

Restart the service with the following command:

# vmon-cli --restart sts'
  impact 0.5
  tag check_id: 'C-60438r889257_chk'
  tag severity: 'medium'
  tag gid: 'V-256763'
  tag rid: 'SV-256763r889259_rule'
  tag stig_id: 'VCST-70-000019'
  tag gtitle: 'SRG-APP-000246-WSR-000149'
  tag fix_id: 'F-60381r889258_fix'
  tag cci: ['CCI-001094']
  tag nist: ['SC-5 (1)']

  describe xml("#{input('serverXmlPath')}") do
    its(['Server/Service/Connector[@port="${bio-custom.http.port}"]/@acceptCount']) { should cmp "#{input('acceptCount')}" }
  end
end
