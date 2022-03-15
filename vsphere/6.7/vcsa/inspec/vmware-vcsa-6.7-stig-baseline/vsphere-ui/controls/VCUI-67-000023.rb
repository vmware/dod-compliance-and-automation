control 'VCUI-67-000023' do
  title "vSphere UI must be configured to show error pages with minimal
information."
  desc  "Web servers will often display error messages to client users with
enough information to aid in the debugging of the error. The information given
back in error messages may display the web server type, version, patches
installed, plug-ins and modules installed, type of code being used by the
hosted application, and any backends being used for data storage. This
information could be used by an attacker to blueprint what type of attacks
might be successful. Therefore, vSphere UI must be configured to not show
server version information in error pages."
  desc  'rationale', ''
  desc  'check', "
    At the command prompt, execute the following command:

    # xmllint --format /usr/lib/vmware-vsphere-ui/server/conf/server.xml |
xmllint --xpath
'/Server/Service/Engine/Host/Valve[@className=\"org.apache.catalina.valves.ErrorReportValve\"]'
-

    Expected result:

    <Valve className=\"org.apache.catalina.valves.ErrorReportValve\"
showServerInfo=\"false\"/>

    If the output of the command does not match the expected result, this is a
finding.
  "
  desc 'fix', "
    Navigate to and open /usr/lib/vmware-vsphere-ui/server/conf/server.xml.

    Locate the following Host block:

    <Host name=\"localhost\"\" ...>
    ...
    </Host>

    Inside this block, add the following on a new line:

    <Valve className=\"org.apache.catalina.valves.ErrorReportValve\"
showServerInfo=\"false\"/>
  "
  impact 0.5
  tag severity: 'medium'
  tag gtitle: 'SRG-APP-000266-WSR-000159'
  tag gid: 'V-239704'
  tag rid: 'SV-239704r679218_rule'
  tag stig_id: 'VCUI-67-000023'
  tag fix_id: 'F-42896r679217_fix'
  tag cci: ['CCI-001312']
  tag nist: ['SI-11 a']

  describe xml("#{input('serverXmlPath')}") do
    its(['Server/Service/Engine/Host/Valve[@className="org.apache.catalina.valves.ErrorReportValve"]/@showServerInfo']) { should cmp 'false' }
  end
end
