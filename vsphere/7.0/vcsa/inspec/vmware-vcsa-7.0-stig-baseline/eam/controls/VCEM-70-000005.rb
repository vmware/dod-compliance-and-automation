# encoding: UTF-8

control 'VCEM-70-000005' do
  title "ESX Agent Manager must record user access in a format that enables
monitoring of remote access."
  desc  "Remote access can be exploited by an attacker to compromise the
server.  By recording all remote access activities, it will be possible to
determine the attacker's location, intent, and degree of success.

    Tomcat can be configured with an AccessLogValve, a component that can be
inserted into the request processing pipeline to provide robust access logging.
The Access Log Valve creates log files in the same format as those created by
standard web servers. When AccessLogValve is properly configured, log files
will contain all the forensic information necessary in the case of a security
incident.
  "
  desc  'rationale', ''
  desc  'check', "
    At the command prompt, execute the following command:

    # xmllint --xpath
'/Server/Service/Engine/Host/Valve[@className=\"org.apache.catalina.valves.AccessLogValve\"]/@pattern'
/usr/lib/vmware-eam/web/conf/server.xml

    Expected result:

    pattern=\"%h %{X-Forwarded-For}i %l %u %t [%I] &quot;%r&quot; %s %b
[Processing time %D msec] &quot;%{User-Agent}i&quot;\"

    If the output does not match the expected result, this is a finding.

  "
  desc  'fix', "
    Navigate to and open /usr/lib/vmware-eam/web/conf/server.xml

    Inside the <Host> node, find the \"AccessLogValve\" <Valve> node and
replace the \"pattern\" element as follows:

    pattern=\"%h %{X-Forwarded-For}i %l %u %t [%I] &quot;%r&quot; %s %b
[Processing time %D msec] &quot;%{User-Agent}i&quot;\"
  "
  impact 0.5
  tag severity: 'medium'
  tag gtitle: 'SRG-APP-000016-WSR-000005'
  tag gid: nil
  tag rid: nil
  tag stig_id: 'VCEM-70-000005'
  tag fix_id: nil
  tag cci: 'CCI-000067'
  tag nist: ['AC-17 (1)']

  describe xml("#{input('serverXmlPath')}") do
    its(['Server/Service/Engine/Host/Valve[@className="org.apache.catalina.valves.AccessLogValve"]/@pattern']) { should cmp ["#{input('accessValvePattern')}"] }
  end

end

