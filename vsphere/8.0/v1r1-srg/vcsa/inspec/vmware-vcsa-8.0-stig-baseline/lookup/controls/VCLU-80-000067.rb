control 'VCLU-80-000067' do
  title 'The vCenter Lookup service "ErrorReportValve showServerInfo" must be set to "false".'
  desc  'The Error Report Valve is a simple error handler for HTTP status codes that will generate and return HTML error pages. It can also be configured to return predefined static HTML pages for specific status codes and/or exception types. Disabling "showServerInfo" will only return the HTTP status code and remove all CSS from the default nonerror-related HTTP responses.'
  desc  'rationale', ''
  desc  'check', "
    At the command prompt, run the following command:

    # xmllint --xpath '/Server/Service/Engine/Host/Valve[@className=\"org.apache.catalina.valves.ErrorReportValve\"]' /usr/lib/vmware-lookupsvc/conf/server.xml

    Example result:

    <Valve className=\"org.apache.catalina.valves.ErrorReportValve\" showServerInfo=\"false\" showReport=\"false\"/>

    If the \"ErrorReportValve\" element is not defined or \"showServerInfo\" is not set to \"false\", this is a finding.
  "
  desc 'fix', "
    Navigate to and open:

    /usr/lib/vmware-lookupsvc/conf/server.xml

    Locate the following Host block:

    <Host ...>
    ...
    </Host>

    Inside this block, add or update the following on a new line:

    <Valve className=\"org.apache.catalina.valves.ErrorReportValve\" showServerInfo=\"false\" showReport=\"false\"/>

    Restart the service with the following command:

    # vmon-cli --restart lookupsvc
  "
  impact 0.5
  tag severity: 'medium'
  tag gtitle: 'SRG-APP-000266-AS-000169'
  tag gid: 'V-VCLU-80-000067'
  tag rid: 'SV-VCLU-80-000067'
  tag stig_id: 'VCLU-80-000067'
  tag cci: ['CCI-001312']
  tag nist: ['SI-11 a']

  # Open server.xml file
  xmlconf = xml(input('serverXmlPath'))

  # Find Host elements with missing ErrorReportValue, or if present, the showServerInfo is not set to false
  describe xmlconf do
    its(["name(//Host[not(Valve[contains(@className, 'ErrorReportValve')])] | //Host[Valve[contains(@className, 'ErrorReportValve')]/@showServerInfo != 'false'])"]) { should cmp [] }
  end
end
