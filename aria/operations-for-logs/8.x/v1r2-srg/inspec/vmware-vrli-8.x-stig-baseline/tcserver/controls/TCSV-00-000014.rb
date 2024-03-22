control 'TCSV-00-000014' do
  title 'The tc Server must produce log records containing sufficient information regarding event details.'
  desc  "
    After a security incident has occurred, investigators will often review log files to determine what happened.  tc Server must create a log entry when users access the system, and the system authenticates the users.

    The logs must contain information about user sessions to include what type of event occurred, when (date and time) events occurred, where within the server the events occurred, the client source of the events, the outcome (success or failure) of the event, and the identity of the user/subject/process associated with the event.

    Like all web servers, tc Server will log the requested URL and the parameters, if any, sent in the request.  This information will enable investigators to determine where in the server an action was requested.

    The AccessLogValve can be defined at multiple levels (Executor, Host, Connector, Context), so at least one must be defined.
  "
  desc  'rationale', ''
  desc  'check', "
    At the command prompt, run the following command:

    # xmllint --xpath \"//*[contains(@className, 'AccessLogValve')]/parent::*\" $CATALINA_BASE/conf/server.xml

    Review all \"Valve\" elements.

    If the pattern= statement does not include a pattern containing the items in the example below, this is a finding.

    EXAMPLE:
    <Host name=\"localhost\" appBase=\"webapps\"
    unpackWARs=\"true\" autoDeploy=\"false\">
    ...
    <Valve className=\"org.apache.catalina.valves.AccessLogValve\" directory=\"logs\"
    prefix=\"localhost_access_log\" suffix=\".txt\"
    pattern=\"%h %l %t %u &quot;%r&quot; %s %b\" />
    ...
    </Host>
  "
  desc 'fix', "
    Edit the $CATALINA_HOME/server.xml file.

    Modify the <Valve className=\"org.apache.catalina.valves.AccessLogValve\" ...> element(s) nested within the <Host> element(s).

    Change the AccessLogValve \"pattern=\" setting to include the items \"%h %l %t %u &quot;%r&quot; %s %b\".

    EXAMPLE:
    <Host name=\"localhost\" appBase=\"webapps\"
    unpackWARs=\"true\" autoDeploy=\"false\">
    ...
    <Valve className=\"org.apache.catalina.valves.AccessLogValve\" directory=\"logs\"
    prefix=\"localhost_access_log\" suffix=\".txt\"
    pattern=\"%h %l %t %u &quot;%r&quot; %s %b\" />
    ...
    </Host>

    Restart the service:
    # systemctl restart loginsight.service
  "
  impact 0.5
  tag severity: 'medium'
  tag gtitle: 'SRG-APP-000095-AS-000056'
  tag satisfies: %w[SRG-APP-000080-AS-000045 SRG-APP-000089-AS-000050 SRG-APP-000091-AS-000052 SRG-APP-000096-AS-000059 SRG-APP-000097-AS-000060 SRG-APP-000098-AS-000061 SRG-APP-000099-AS-000062 SRG-APP-000100-AS-000063 SRG-APP-000343-AS-000030 SRG-APP-000375-AS-000211]
  tag gid: 'V-TCSV-00-000014'
  tag rid: 'SV-TCSV-00-000014'
  tag stig_id: 'TCSV-00-000014'
  tag cci: %w[CCI-000130 CCI-000131 CCI-000132 CCI-000133 CCI-000134 CCI-000166 CCI-000169 CCI-000172 CCI-001487 CCI-001889 CCI-002234]
  tag nist: ['AC-6 (9)', 'AU-10', 'AU-12 a', 'AU-12 c', 'AU-3', 'AU-8 b']

  # At least one should exist
  count = 0
  # Open server.xml file
  xmlconf = xml("#{input('catalinaBase')}/conf/server.xml")
  # Get an array of patterns from all the AccessLogValve elements
  xmlconf['//*/Valve[@className="org.apache.catalina.valves.AccessLogValve"]/@pattern'].each do |pattern|
    count += 1
    # compare each part of the pattern to the given input array
    input('accessLogPattern').each do |item|
      describe pattern do
        it { should include item }
      end
    end
  end

  # If context.xml file paths have been provided, do the same process as above for each file in the array
  input('contextXmlFiles').each do |context|
    if file(context).exist?
      contextconf = xml(context)
      contextconf['//*/Valve[@className="org.apache.catalina.valves.AccessLogValve"]/@pattern'].each do |pattern|
        count += 1
        input('accessLogPattern').each do |item|
          describe pattern do
            it { should include item }
          end
        end
      end
    else
      describe 'Context file not found' do
        skip 'Context file not found'
      end
    end
  end

  describe "Checking for at least one AccessLogValve entry (count #{count})" do
    subject { count }
    it { should > 0 }
  end
end
