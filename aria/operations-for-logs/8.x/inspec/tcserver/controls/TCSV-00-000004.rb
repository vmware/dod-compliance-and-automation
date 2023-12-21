control 'TCSV-00-000004' do
  title 'Logging must be configured for each tc Server application context.'
  desc  "
    Logging must be utilized in order to track system activity, assist in diagnosing system issues, and provide evidence needed for forensic investigations post security incident.

    tc Server logging configuration is achieved through the <Valve> object. A Valve is an interceptor like element that, when inserted in a Container (Context, Host, or Engine), intercepts all the incoming HTTP requests before they reach the application.
  "
  desc  'rationale', ''
  desc  'check', "
    Ensure that an AccessLogValue object exists within a Container element (Context, Host, or Engine).

    To find all the AccessLogValve objects, and their associated parent node, run the following command:

    # xmllint --xpath \"//Valve[contains(@className, 'AccessLogValve')]/parent::*\" $CATALINA_BASE/conf/server.xml

    If a <Valve className=\"org.apache.catalina.valves.AccessLogValve\" .../> element is not defined within one of the Container elements, this is a finding.

    EXAMPLE:
    <Host
    ...
    <Valve className=\"org.apache.catalina.valves.AccessLogValve\" directory=\"logs\"
    prefix=\"host_name_log\" suffix=\".txt\"
    pattern=\"%h %l %t %u &quot;%r&quot; %s %b\" />
    ...
    />
  "
  desc 'fix', "
    Edit the $CATALINA_HOME/server.xml file.

    Create or edit a <Valve> element that is nested within the <Host> container.

    EXAMPLE:
    <Host
    ...
    <Valve className=\"org.apache.catalina.valves.AccessLogValve\" directory=\"logs\"
    prefix=\"application_name_log\" suffix=\".txt\"
    pattern=\"%h %l %t %u &quot;%r&quot; %s %b\" />
    ...
    />

    Restart the service:
    # systemctl restart loginsight.service
  "
  impact 0.5
  tag severity: 'medium'
  tag gtitle: 'SRG-APP-000016-AS-000013'
  tag satisfies: %w(SRG-APP-000090-AS-000051 SRG-APP-000495-AS-000220 SRG-APP-000499-AS-000224 SRG-APP-000503-AS-000228)
  tag gid: 'V-TCSV-00-000004'
  tag rid: 'SV-TCSV-00-000004'
  tag stig_id: 'TCSV-00-000004'
  tag cci: %w(CCI-000067 CCI-000171 CCI-000172)
  tag nist: ['AC-17 (1)', 'AU-12 b', 'AU-12 c']

  # Get path to server.xml file
  xmlconf = xml("#{input('catalinaBase')}/conf/server.xml")

  # Check for an AccessLogValve
  describe xmlconf do
    its(["name(//Valve[contains(@className, 'AccessLogValve')])"]) { should_not cmp [] }
  end
end
