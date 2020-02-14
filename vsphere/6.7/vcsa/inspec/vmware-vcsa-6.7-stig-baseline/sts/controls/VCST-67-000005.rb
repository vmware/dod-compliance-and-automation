control "VCST-67-000005" do
  title "The Security Token Service must record user access in a format that
enables monitoring of remote access."
  desc  "Remote access can be exploited by an attacker to compromise the
server.  By recording all remote access activities, it will be possible to
determine the attacker's location, intent, and degree of success.

    Tomcat can be configured with an AccessLogValve, a component that can be
inserted into the request processing pipeline to provide robust access logging.
The Access Log Valve creates log files in the same format as those created by
standard web servers. When AccessLogValve is properly configured, log files
will contain all the forensic information necessary in the case of a security
incident."
  impact 0.5
  tag severity: "CAT II"
  tag gtitle: "SRG-APP-000016-WSR-000005"
  tag gid: nil
  tag rid: "VCST-67-000005"
  tag stig_id: "VCST-67-000005"
  tag cci: "CCI-000067"
  tag nist: ["AC-17 (1)", "Rev_4"]
  desc 'check', "At the command prompt, execute the following command:

# xmllint --format /usr/lib/vmware-sso/vmware-sts/conf/server.xml | sed '2
s/xmlns=\".*\"//g' | xmllint --xpath
'/Server/Service/Engine/Host/Valve[@className=\"org.apache.catalina.valves.AccessLogValve\"]'/@pattern
-

Expected result:

pattern=\"%h %{X-Forwarded-For}i %l %u %t &quot;%r&quot; %s %b
&quot;%{User-Agent}i&quot;\" resolveHosts=\"false\"
prefix=\"localhost_access_log\" suffix=\".txt\" />

If the output does not match the expected result, this is a finding.

"
  desc 'fix', "Navigate to and open /usr/lib/vmware-sso/vmware-sts/conf/server.xml

Configure the <Host> node with the two nodes below.

<Valve className=\"org.apache.catalina.valves.RemoteIpValve\"
httpServerPort=\"80\" httpsServerPort=\"443\"
protocolHeader=\"x-forwarded-proto\" proxiesHeader=\"x-forwarded-by\"
remoteIpHeader=\"x-forwarded-for\" requestAttributesEnabled=\"true\"
internalProxies=\"127\\.0\\.0\\.1\" />

<Valve className=\"org.apache.catalina.valves.AccessLogValve\"
directory=\"logs\" pattern=\"%h %{X-Forwarded-For}i %l %u %t &quot;%r&quot; %s
%b &quot;%{User-Agent}i&quot;\" resolveHosts=\"false\"
prefix=\"localhost_access_log\" suffix=\".txt\" />"

  describe xml('/usr/lib/vmware-sso/vmware-sts/conf/server.xml') do
    its(['Server/Service/Engine/Host/Valve[@className="org.apache.catalina.valves.AccessLogValve"]/@pattern']) { should cmp ['%h %{X-Forwarded-For}i %l %u %t &quot;%r&quot; %s %b &quot;%{User-Agent}i&quot;'] }
  end

end