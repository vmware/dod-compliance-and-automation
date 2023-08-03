control 'VCST-70-000025' do
  title 'The Security Token Service must not enable support for TRACE requests.'
  desc '"TRACE" is a technique for a user to request internal information about Tomcat. This is useful during product development but should not be enabled in production. Allowing an attacker to conduct a TRACE operation against the Security Token Service will expose information that would be useful to perform a more targeted attack.

The Security Token Service provides the "allowTrace" parameter as means to disable responding to TRACE requests.'
  desc 'check', 'At the command prompt, run the following command:

# grep allowTrace /usr/lib/vmware-sso/vmware-sts/conf/server.xml

If "allowTrace" is set to "true", this is a finding.

If no line is returned, this is not a finding.'
  desc 'fix', %q(Navigate to and open:

/usr/lib/vmware-sso/vmware-sts/conf/server.xml

Locate and remove the 'allowTrace="true"' setting.

Restart the service with the following command:

# vmon-cli --restart sts)
  impact 0.5
  tag check_id: 'C-60444r889275_chk'
  tag severity: 'medium'
  tag gid: 'V-256769'
  tag rid: 'SV-256769r889277_rule'
  tag stig_id: 'VCST-70-000025'
  tag gtitle: 'SRG-APP-000266-WSR-000160'
  tag fix_id: 'F-60387r889276_fix'
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
