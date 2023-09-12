control 'VRPU-8X-000067' do
  title 'The UI service "ErrorReportValve showServerInfo" must be set to "false".'
  desc  'The Error Report Valve is a simple error handler for HTTP status codes that will generate and return HTML error pages. It can also be configured to return pre-defined static HTML pages for specific status codes and/or exception types. Disabling showServerInfo will only return the HTTP status code and remove all CSS from the default non-error related HTTP responses.'
  desc  'rationale', ''
  desc  'check', "
    At the command prompt, run the following command:

    # xmllint --xpath \"//*[contains(@className, 'ErrorReportValve')]/parent::*\" $CATALINA_BASE/conf/server.xml

    If the ErrorReportValve element is not defined or showServerInfo is not set to \"false\", this is a finding.

    EXAMPLE:
    <Host ...>
    ...
    <Valve className=\"org.apache.catalina.valves.ErrorReportValve\" showServerInfo=\"false\"/>
    ...
    </Host>
  "
  desc 'fix', "
    Edit the $CATALINA_BASE/conf/server.xml file.

    Create or modify an ErrorReportValve <Valve> element nested within each <Host> element.

    EXAMPLE:
    <Host name=\"localhost\" appBase=\"webapps\"
    unpackWARs=\"true\" autoDeploy=\"false\">
    ...
    <Valve className=\"org.apache.catalina.valves.ErrorReportValve\"
    showServerInfo=\"false\" />
    ...
    </Host>

    Restart the service:
    # systemctl restart vmware-vcops-web.service
  "
  impact 0.5
  tag severity: 'medium'
  tag gtitle: 'SRG-APP-000266-AS-000169'
  tag gid: 'V-VRPU-8X-000067'
  tag rid: 'SV-VRPU-8X-000067'
  tag stig_id: 'VRPU-8X-000067'
  tag cci: ['CCI-001312']
  tag nist: ['SI-11 a']

  # Open server.xml file
  xmlconf = xml(input('ui-serverXmlPath'))

  # Find Host elements with missing ErrorReportValue, or if present, the showServerInfo is not set to false
  describe xmlconf do
    its(["name(//Host[not(Valve[contains(@className, 'ErrorReportValve')])] | //Host[Valve[contains(@className, 'ErrorReportValve')]/@showServerInfo != 'false'])"]) { should cmp [] }
  end
end
