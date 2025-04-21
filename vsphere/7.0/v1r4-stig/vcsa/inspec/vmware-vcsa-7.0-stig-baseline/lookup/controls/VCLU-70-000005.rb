control 'VCLU-70-000005' do
  title 'Lookup Service must record user access in a format that enables monitoring of remote access.'
  desc %q(Remote access can be exploited by an attacker to compromise the server. By recording all remote access activities, it will be possible to determine the attacker's location, intent, and degree of success.

Tomcat can be configured with an "AccessLogValve", a component that can be inserted into the request processing pipeline to provide robust access logging. The "AccessLogValve" creates log files in the same format as those created by standard web servers. When "AccessLogValve" is properly configured, log files will contain all the forensic information necessary in the case of a security incident.

)
  desc 'check', %q(At the command prompt, run the following command:

# xmllint --xpath '/Server/Service/Engine/Host/Valve[@className="org.apache.catalina.valves.AccessLogValve"]/@pattern' /usr/lib/vmware-lookupsvc/conf/server.xml

Expected result:

pattern="%t %I [RemoteIP] %{X-Forwarded-For}i %u [Request] %h:%{remote}p to local %{local}p - %H %m %U%q    [Response] %s - %b bytes    [Perf] process %Dms / commit %Fms / conn [%X]"

If the output does not match the expected result, this is a finding.)
  desc 'fix', 'Navigate to and open:

/usr/lib/vmware-lookupsvc/conf/server.xml

Inside the <Host> node, find the "AccessLogValve" <Valve> node and replace the "pattern" element as follows:

pattern="%t %I [RemoteIP] %{X-Forwarded-For}i %u [Request] %h:%{remote}p to local %{local}p - %H %m %U%q    [Response] %s - %b bytes    [Perf] process %Dms / commit %Fms / conn [%X]"

Restart the service with the following command:

# vmon-cli --restart lookupsvc'
  impact 0.5
  tag check_id: 'C-60385r888719_chk'
  tag severity: 'medium'
  tag gid: 'V-256710'
  tag rid: 'SV-256710r888721_rule'
  tag stig_id: 'VCLU-70-000005'
  tag gtitle: 'SRG-APP-000016-WSR-000005'
  tag fix_id: 'F-60328r888720_fix'
  tag satisfies: ['SRG-APP-000016-WSR-000005', 'SRG-APP-000093-WSR-000053', 'SRG-APP-000095-WSR-000056', 'SRG-APP-000096-WSR-000057', 'SRG-APP-000097-WSR-000058', 'SRG-APP-000098-WSR-000059', 'SRG-APP-000098-WSR-000060', 'SRG-APP-000099-WSR-000061', 'SRG-APP-000100-WSR-000064', 'SRG-APP-000375-WSR-000171', 'SRG-APP-000374-WSR-000172']
  tag cci: ['CCI-000067', 'CCI-000130', 'CCI-000131', 'CCI-000132', 'CCI-000133', 'CCI-000134', 'CCI-001462', 'CCI-001487', 'CCI-001889', 'CCI-001890']
  tag nist: ['AC-17 (1)', 'AU-3 a', 'AU-3 b', 'AU-3 c', 'AU-3 d', 'AU-3 e', 'AU-14 (2)', 'AU-3 f', 'AU-8 b', 'AU-8 b']

  describe xml("#{input('serverXmlPath')}") do
    its(['Server/Service/Engine/Host/Valve[@className="org.apache.catalina.valves.AccessLogValve"]/@pattern']) { should cmp ["#{input('accessValvePattern')}"] }
  end
end
