control 'VCUI-67-000005' do
  title "vSphere UI must record user access in a format that enables monitoring
of remote access."
  desc  "Remote access can be exploited by an attacker to compromise the
server. By recording all remote access activities, it will be possible to
determine the attacker's location, intent, and degree of success.

    Tomcat can be configured with an \"AccessLogValve\", a component that can
be inserted into the request processing pipeline to provide robust access
logging. The AccessLogValve creates log files in the same format as those
created by standard web servers. When AccessLogValve is properly configured,
log files will contain all the forensic information necessary in the case of a
security incident.
  "
  desc  'rationale', ''
  desc  'check', "
    At the command prompt, execute the following command:

    # xmllint --format /usr/lib/vmware-vsphere-ui/server/conf/server.xml |
xmllint --xpath
'/Server/Service/Engine/Host/Valve[@className=\"org.apache.catalina.valves.AccessLogValve\"]'/@pattern
-

    Expected result:

    pattern=\"%h %{x-forwarded-for}i %l %u %t %r %s %b %{#hashedSessionId#}s %I
%D\"

    If the output does not match the expected result, this is a finding.
  "
  desc 'fix', "
    Navigate to and open /usr/lib/vmware-vsphere-ui/server/conf/server.xml.

    Ensure the log pattern in the \"org.apache.catalina.valves.AccessLogValve\"
node is set to the following:

    pattern=\"pattern=\"%h %{x-forwarded-for}i %l %u %t %r %s %b
%{#hashedSessionId#}s %I %D\"\"
  "
  impact 0.5
  tag severity: 'medium'
  tag gtitle: 'SRG-APP-000016-WSR-000005'
  tag satisfies: ['SRG-APP-000016-WSR-000005', 'SRG-APP-000089-WSR-000047',
'SRG-APP-000095-WSR-000056', 'SRG-APP-000096-WSR-000057',
'SRG-APP-000097-WSR-000058', 'SRG-APP-000098-WSR-000059',
'SRG-APP-000098-WSR-000060', 'SRG-APP-000099-WSR-000061',
'SRG-APP-000100-WSR-000064', 'SRG-APP-000374-WSR-000172',
'SRG-APP-000375-WSR-000171']
  tag gid: 'V-239686'
  tag rid: 'SV-239686r816774_rule'
  tag stig_id: 'VCUI-67-000005'
  tag fix_id: 'F-42878r816773_fix'
  tag cci: ['CCI-000067', 'CCI-000130', 'CCI-000131', 'CCI-000132',
'CCI-000133', 'CCI-000134', 'CCI-000213', 'CCI-001462', 'CCI-001464',
'CCI-001487', 'CCI-001889', 'CCI-001890']
  tag nist: ['AC-17 (1)', 'AU-3', 'AU-3', 'AU-3', 'AU-3', 'AU-3', 'AC-3',
'AU-14 (2)', 'AU-14 (1)', 'AU-3', 'AU-8 b', 'AU-8 b']

  describe xml("#{input('serverXmlPath')}") do
    its(['Server/Service/Engine/Host/Valve[@className="org.apache.catalina.valves.AccessLogValve"]/@pattern']) { should cmp ["#{input('accessValvePattern')}"] }
  end
end
