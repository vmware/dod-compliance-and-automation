control 'VCST-67-000024' do
  title "The Security Token Service must be configured to show error pages with
minimal information."
  desc  "Web servers will often display error messages to client users,
displaying enough information to aid in the debugging of the error. The
information given back in error messages may display the web server type,
version, patches installed, plug-ins and modules installed, type of code being
used by the hosted application, and any backends being used for data storage.
This information could be used by an attacker to blueprint what type of attacks
might be successful. As such, the Security Token Service must be configured to
not show server version information in error messages."
  desc  'rationale', ''
  desc  'check', "
    Connect to the PSC, whether external or embedded.

    At the command prompt, execute the following command:

    # xmllint --format /usr/lib/vmware-sso/vmware-sts/conf/server.xml | sed '2
s/xmlns=\".*\"//g' | xmllint --xpath
'/Server/Service/Engine/Host/Valve[@className=\"org.apache.catalina.valves.ErrorReportValve\"]'
-

    Expected result:

    <Valve className=\"org.apache.catalina.valves.ErrorReportValve\"
showReport=\"false\" showServerInfo=\"false\"/>

    If the output does not match the expected result, this is a finding.
  "
  desc 'fix', "
    Connect to the PSC, whether external or embedded.

    Navigate to and open /usr/lib/vmware-sso/vmware-sts/conf/server.xml.

    Locate the following Host block:

    <Host appBase=\"webapps\" ...>
    ...
    </Host>

    Inside this block, add the following on a new line:

    <Valve className=\"org.apache.catalina.valves.ErrorReportValve\"
showReport=\"false\" showServerInfo=\"false\" />
  "
  impact 0.5
  tag severity: 'medium'
  tag gtitle: 'SRG-APP-000266-WSR-000159'
  tag gid: 'V-239675'
  tag rid: 'SV-239675r816750_rule'
  tag stig_id: 'VCST-67-000024'
  tag fix_id: 'F-42867r816749_fix'
  tag cci: ['CCI-001312']
  tag nist: ['SI-11 a']

  describe xml("#{input('serverXmlPath')}") do
    its(['Server/Service/Engine/Host/Valve[@className="org.apache.catalina.valves.ErrorReportValve"]/@showServerInfo']) { should cmp 'false' }
    its(['Server/Service/Engine/Host/Valve[@className="org.apache.catalina.valves.ErrorReportValve"]/@showReport']) { should cmp 'false' }
  end
end
