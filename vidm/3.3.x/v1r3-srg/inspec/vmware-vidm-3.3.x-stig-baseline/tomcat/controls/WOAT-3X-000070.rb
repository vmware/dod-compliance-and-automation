control 'WOAT-3X-000070' do
  title 'Workspace ONE Access must be configured to not show error reports.'
  desc  'Web servers will often display error messages to client users displaying enough information to aid in the debugging of the error. The information given back in error messages may display the web server type, version, patches installed, plug-ins and modules installed, type of code being used by the hosted application, and any backends being used for data storage. This information could be used by an attacker to blueprint what type of attacks might be successful.'
  desc  'rationale', ''
  desc  'check', "
    At the command prompt, execute the following command:

    # xmllint --xpath '/Server/Service/Engine/Host/Valve[@className=\"org.apache.catalina.valves.ErrorReportValve\"]' /opt/vmware/horizon/workspace/conf/server.xml

    Expected result:

    <Valve className=\"org.apache.catalina.valves.ErrorReportValve\" showServerInfo=\"false\" showReport=\"false\"/>

    If the output of the command does not match the expected result, this is a finding.
  "
  desc 'fix', "
    Navigate to and open:

    /opt/vmware/horizon/workspace/conf/server.xml

    Locate the following Host block:

    <Host ...>
    ...
    </Host>

    Inside this block, add the following on a new line:

    <Valve className=\"org.apache.catalina.valves.ErrorReportValve\" showServerInfo=\"false\" showReport=\"false\"/>
  "
  impact 0.5
  tag severity: 'medium'
  tag gtitle: 'SRG-APP-000266-WSR-000159'
  tag gid: 'V-WOAT-3X-000070'
  tag rid: 'SV-WOAT-3X-000070'
  tag stig_id: 'WOAT-3X-000070'
  tag cci: ['CCI-001312']
  tag nist: ['SI-11 a']

  describe xml("#{input('serverXmlPath')}") do
    its(['Server/Service/Engine/Host/Valve[@className="org.apache.catalina.valves.ErrorReportValve"]/@showServerInfo']) { should cmp 'false' }
    its(['Server/Service/Engine/Host/Valve[@className="org.apache.catalina.valves.ErrorReportValve"]/@showReport']) { should cmp 'false' }
  end
end
