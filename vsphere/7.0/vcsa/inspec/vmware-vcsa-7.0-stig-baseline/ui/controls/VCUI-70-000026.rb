control 'VCUI-70-000026' do
  title 'vSphere UI must not enable support for TRACE requests.'
  desc '"TRACE" is a technique for a user to request internal information about Tomcat. This is useful during product development but should not be enabled in production. Allowing an attacker to conduct a TRACE operation against the web service will expose information that would be useful to perform a more targeted attack. vSphere UI provides the "allowTrace" parameter as means to disable responding to TRACE requests.'
  desc 'check', 'At the command prompt, run the following command:

# grep allowTrace /usr/lib/vmware-vsphere-ui/server/conf/server.xml

If "allowTrace" is set to "true", this is a finding.

If no line is returned, this is not a finding.'
  desc 'fix', %q(Navigate to and open:

/usr/lib/vmware-vsphere-ui/server/conf/server.xml

Navigate to and locate 'allowTrace="true"'.

Remove the 'allowTrace="true"' setting.

Restart the service with the following command:

# vmon-cli --restart vsphere-ui)
  impact 0.5
  tag check_id: 'C-60478r889406_chk'
  tag severity: 'medium'
  tag gid: 'V-256803'
  tag rid: 'SV-256803r889408_rule'
  tag stig_id: 'VCUI-70-000026'
  tag gtitle: 'SRG-APP-000266-WSR-000160'
  tag fix_id: 'F-60421r889407_fix'
  tag cci: ['CCI-001312']
  tag nist: ['SI-11 a']

  describe.one do
    describe xml("#{input('serverXmlPath')}") do
      its(['Server/Service/Connector/attribute::allowTrace']) { should eq [] }
    end

    describe xml("#{input('serverXmlPath')}") do
      its(['Server/Service/Connector/attribute::allowTrace']) { should cmp 'false' }
    end
  end
end
