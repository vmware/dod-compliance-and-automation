# encoding: UTF-8

control 'VCST-70-000005' do
  title "The Security Token Service must record user access in a format that
enables monitoring of remote access."
  desc  "Logging must be started as soon as possible when a service starts and
as late as possible when a service is stopped. Many forms of suspicious actions
can be detected by analyzing logs for unexpected service starts and stops.
Also, by starting to log immediately after a service starts, it becomes more
difficult for suspicious activity to go unlogged."
  desc  'rationale', ''
  desc  'check', "
    At the command prompt, execute the following command:

    # xmllint --format /usr/lib/vmware-sso/vmware-sts/conf/server.xml | sed '2
s/xmlns=\".*\"//g' | xmllint --xpath
'/Server/Service/Engine/Host/Valve[@className=\"org.apache.catalina.valves.AccessLogValve\"]/@pattern'
-

    Expected result:

    pattern=\"%t %I [RemoteIP] %{X-Forwarded-For}i %u [Request] %h:%{remote}p
to local %{local}p - %H %m %U%q    [Response] %s - %b bytes    [Perf] process
%Dms / commit %Fms / conn [%X]\"

    If the output does not match the expected result, this is a finding.
  "
  desc  'fix', "
    Navigate to and open:

    /usr/lib/vmware-sso/vmware-sts/conf/server.xml

    Inside the <Host> node, find the \"AccessLogValve\" <Valve> node and
replace the \"pattern\" element as follows:

    pattern=\"%t %I [RemoteIP] %{X-Forwarded-For}i %u [Request] %h:%{remote}p
to local %{local}p - %H %m %U%q    [Response] %s - %b bytes    [Perf] process
%Dms / commit %Fms / conn [%X]\"
  "
  impact 0.5
  tag severity: 'medium'
  tag gtitle: 'SRG-APP-000016-WSR-000005'
  tag gid: nil
  tag rid: nil
  tag stig_id: 'VCST-70-000005'
  tag fix_id: nil
  tag cci: 'CCI-000067'
  tag nist: ['AC-17 (1)']

  describe xml("#{input('serverXmlPath')}") do
    its(['Server/Service/Engine/Host/Valve[@className="org.apache.catalina.valves.AccessLogValve"]/@pattern']) { should cmp ["#{input('accessValvePattern')}"] }
  end

end

