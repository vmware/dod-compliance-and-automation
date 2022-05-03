control 'VCEM-70-000027' do
  title 'ESX Agent Manager must not enable support for TRACE requests.'
  desc  '"Trace" is a technique for a user to request internal information about Tomcat. This is useful during product development, but should not be enabled in production. Allowing an attacker to conduct a TRACE operation against ESX Agent Manager will expose information that would be useful to perform a more targeted attack. ESX Agent Manager provides the "allowTrace" parameter as means to disable responding to TRACE requests.'
  desc  'rationale', ''
  desc  'check', "
    At the command prompt, execute the following command:

    # grep allowTrace /usr/lib/vmware-eam/web/conf/server.xml

    If \"allowTrace\" is set to \"true\", this is a finding.

    If no line is returned, this is NOT a finding.
  "
  desc 'fix', "
    Navigate to and open:

    /usr/lib/vmware-eam/web/conf/server.xml

    Navigate to and locate:

    'allowTrace=\"true\"'

    Remove the 'allowTrace=\"true\"' setting.

    Restart the service with the following command:

    # vmon-cli --restart eam
  "
  impact 0.5
  tag severity: 'medium'
  tag gtitle: 'SRG-APP-000266-WSR-000160'
  tag gid: nil
  tag rid: nil
  tag stig_id: 'VCEM-70-000027'
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
