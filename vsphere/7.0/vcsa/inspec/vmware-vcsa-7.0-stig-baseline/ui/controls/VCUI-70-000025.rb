control 'VCUI-70-000025' do
  title 'vSphere UI must be configured to show error pages with minimal information.'
  desc  "
    Web servers will often display error messages to client users with enough information to aid in the debugging of the error. The information given back in error messages may display the web server type, version, patches installed, plug-ins and modules installed, type of code being used by the hosted application, and any backends being used for data storage.

    This information could be used by an attacker to blueprint what type of attacks might be successful. Therefore, vSphere UI must be configured to not show server version information in error pages.
  "
  desc  'rationale', ''
  desc  'check', "
    At the command prompt, execute the following command:

    # xmllint --format /usr/lib/vmware-vsphere-ui/server/conf/server.xml | xmllint --xpath '/Server/Service/Engine/Host/Valve[@className=\"org.apache.catalina.valves.ErrorReportValve\"]' -

    Expected result:

    <Valve className=\"org.apache.catalina.valves.ErrorReportValve\" showServerInfo=\"false\" showReport=\"false\"/>

    If the output of the command does not match the expected result, this is a finding.
  "
  desc 'fix', "
    Navigate to and open:

     /usr/lib/vmware-vsphere-ui/server/conf/server.xml

    Locate the following Host block:

    <Host ...>
    ...
    </Host>

    Inside this block, remove any existing Valve with className=\"org.apache.catalina.valves.ErrorReportValve\" and add the following:

    <Valve className=\"org.apache.catalina.valves.ErrorReportValve\" showServerInfo=\"false\" showReport=\"false\"/>

    Restart the service with the following command:

    # vmon-cli --restart vsphere-ui
  "
  impact 0.5
  tag severity: 'medium'
  tag gtitle: 'SRG-APP-000266-WSR-000159'
  tag gid: nil
  tag rid: nil
  tag stig_id: 'VCUI-70-000025'
  tag cci: ['CCI-001312']
  tag nist: ['SI-11 a']

  describe xml("#{input('serverXmlPath')}") do
    its(['Server/Service/Engine/Host/Valve[@className="org.apache.catalina.valves.ErrorReportValve"]/@showServerInfo']) { should cmp 'false' }
    its(['Server/Service/Engine/Host/Valve[@className="org.apache.catalina.valves.ErrorReportValve"]/@showReport']) { should cmp 'false' }
  end
end
