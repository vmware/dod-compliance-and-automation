control 'WOAT-3X-000072' do
  title 'Workspace ONE Access must not enable support for TRACE requests.'
  desc  '"Trace" is a technique for a user to request internal information about Tomcat. This is useful during product development, but should not be enabled in production.  Allowing a attacker to conduct a Trace operation against Workspace ONE Access will expose information that would be useful to perform a more targeted attack. Workspace ONE Access provides the allowTrace parameter as means to disable responding to Trace requests.'
  desc  'rationale', ''
  desc  'check', "
    At the command prompt, execute the following command:

    # grep allowTrace /opt/vmware/horizon/workspace/conf/server.xml

    If allowTrace is set to \"true\", this is a finding.

    If no line is returned, this is NOT a finding.
  "
  desc 'fix', "
    Navigate to and open:

    /opt/vmware/horizon/workspace/conf/server.xml

    Navigate to and remove the 'allowTrace=\"true\"' setting.
  "
  impact 0.5
  tag severity: 'medium'
  tag gtitle: 'SRG-APP-000266-WSR-000160'
  tag gid: 'V-WOAT-3X-000072'
  tag rid: 'SV-WOAT-3X-000072'
  tag stig_id: 'WOAT-3X-000072'
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
