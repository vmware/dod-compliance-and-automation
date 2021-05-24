# encoding: UTF-8

control 'VCST-70-000024' do
  title "The Security Token Service must be configured to not show error
reports."
  desc  "\"TRACE\" is a technique for a user to request internal information
about Tomcat. This is useful during product development, but should not be
enabled in production.  Allowing a attacker to conduct a TRACE operation
against the Security Token Service will expose information that would be useful
to perform a more targeted attack.

    The Security Token Service provides the \"allowTrace\" parameter as means
to disable responding to TRACE requests.
  "
  desc  'rationale', ''
  desc  'check', "
    At the command prompt, execute the following command:

    # xmllint --xpath
'/Server/Service/Engine/Host/Valve[@className=\"org.apache.catalina.valves.ErrorReportValve\"]'
/usr/lib/vmware-sso/vmware-sts/conf/server.xml

    Expected result:

    <Valve className=\"org.apache.catalina.valves.ErrorReportValve\"
showReport=\"false\" showServerInfo=\"false\"/>

    If the output does not match the expected result, this is a finding.
  "
  desc  'fix', "
    Navigate to and open:

    /usr/lib/vmware-sso/vmware-sts/conf/server.xml

    Locate the following Host block:

    <Host ...>
    ...
    </Host>

    Inside this block, remove any existing Valve with
className=\"org.apache.catalina.valves.ErrorReportValve\" and add the following:

    <Valve className=\"org.apache.catalina.valves.ErrorReportValve\"
showServerInfo=\"false\" showReport=\"false\"/>
  "
  impact 0.5
  tag severity: 'medium'
  tag gtitle: 'SRG-APP-000266-WSR-000159'
  tag gid: nil
  tag rid: nil
  tag stig_id: 'VCST-70-000024'
  tag fix_id: nil
  tag cci: 'CCI-001312'
  tag nist: ['SI-11 a']

  describe xml("#{input('serverXmlPath')}") do
    its(['Server/Service/Engine/Host/Valve[@className="org.apache.catalina.valves.ErrorReportValve"]/@showServerInfo']) { should cmp "false" }
    its(['Server/Service/Engine/Host/Valve[@className="org.apache.catalina.valves.ErrorReportValve"]/@showReport']) { should cmp "false" }
  end

end

