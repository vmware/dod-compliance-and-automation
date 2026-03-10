control 'VCST-70-000024' do
  title 'The Security Token Service must be configured to not show error reports.'
  desc 'Web servers will often display error messages to client users, displaying enough information to aid in the debugging of the error. The information given back in error messages may display the web server type, version, patches installed, plug-ins and modules installed, type of code being used by the hosted application, and any backends being used for data storage.

This information could be used by an attacker to blueprint what type of attacks might be successful. Therefore, the Security Token Service must be configured to not show server version information in error messages.'
  desc 'check', %q(At the command prompt, run the following command:

# xmllint --xpath '/Server/Service/Engine/Host/Valve[@className="org.apache.catalina.valves.ErrorReportValve"]' /usr/lib/vmware-sso/vmware-sts/conf/server.xml

Expected result:

<Valve className="org.apache.catalina.valves.ErrorReportValve" showReport="false" showServerInfo="false"/>

If the output does not match the expected result, this is a finding.)
  desc 'fix', 'Navigate to and open:

/usr/lib/vmware-sso/vmware-sts/conf/server.xml

Locate the following Host block:

<Host ...>
...
</Host>

Inside this block, remove any existing Valve with className="org.apache.catalina.valves.ErrorReportValve" and add the following:

<Valve className="org.apache.catalina.valves.ErrorReportValve" showServerInfo="false" showReport="false"/>

Restart the service with the following command:

# vmon-cli --restart sts'
  impact 0.5
  tag check_id: 'C-60443r889272_chk'
  tag severity: 'medium'
  tag gid: 'V-256768'
  tag rid: 'SV-256768r889274_rule'
  tag stig_id: 'VCST-70-000024'
  tag gtitle: 'SRG-APP-000266-WSR-000159'
  tag fix_id: 'F-60386r889273_fix'
  tag cci: ['CCI-001312']
  tag nist: ['SI-11 a']

  describe xml("#{input('serverXmlPath')}") do
    its(['Server/Service/Engine/Host/Valve[@className="org.apache.catalina.valves.ErrorReportValve"]/@showServerInfo']) { should cmp 'false' }
    its(['Server/Service/Engine/Host/Valve[@className="org.apache.catalina.valves.ErrorReportValve"]/@showReport']) { should cmp 'false' }
  end
end
