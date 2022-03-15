control 'VCFL-67-000025' do
  title 'vSphere Client must not enable support for TRACE requests.'
  desc "\"Trace\" is a technique for a user to request internal information
about Tomcat. This is useful during product development but should not be
enabled in production.

    Allowing an attacker to conduct a Trace operation against the Security
Token Service will expose information that would be useful to perform a more
targeted attack. vSphere Client provides the \"allowTrace\" parameter as a
means to disable responding to Trace requests.
  "
  desc  'rationale', ''
  desc  'check', "
    At the command prompt, execute the following command:

    # grep allowTrace
/usr/lib/vmware-vsphere-client/server/configuration/tomcat-server.xml

    If \"allowTrace\" is set to \"true\", this is a finding.

    If no line is returned, this is NOT a finding.
  "
  desc 'fix', "
    Navigate to and open
/usr/lib/vmware-vsphere-client/server/configuration/tomcat-server.xml.

    Navigate to and locate:

    'allowTrace=\"true\"'

    Remove the 'allowTrace=\"true\"' setting.
  "
  impact 0.5
  tag severity: 'medium'
  tag gtitle: 'SRG-APP-000266-WSR-000160'
  tag gid: 'V-239766'
  tag rid: 'SV-239766r679525_rule'
  tag stig_id: 'VCFL-67-000025'
  tag fix_id: 'F-42958r679524_fix'
  tag cci: ['CCI-001312']
  tag nist: ['SI-11 a']

  describe.one do
    describe xml('/usr/lib/vmware-vsphere-client/server/configuration/tomcat-server.xml') do
      its(['Server/Service/Connector/attribute::allowTrace']) { should eq [] }
    end

    describe xml('/usr/lib/vmware-vsphere-client/server/configuration/tomcat-server.xml') do
      its(['Server/Service/Connector/attribute::allowTrace']) { should cmp 'false' }
    end
  end
end
