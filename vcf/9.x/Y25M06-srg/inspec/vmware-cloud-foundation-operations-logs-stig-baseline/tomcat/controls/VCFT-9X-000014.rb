control 'VCFT-9X-000014' do
  title 'The VMware Cloud Foundation Operations for Logs Loginsight service must produce log records containing information to establish what type of events occurred.'
  desc  "
    Information system logging capability is critical for accurate forensic analysis.  Without being able to establish what type of event occurred, it would be difficult to establish, correlate, and investigate the events relating to an incident or identify those responsible.

    Log record content that may be necessary to satisfy the requirement of this control includes time stamps, source and destination addresses, user/process identifiers, event descriptions, success/fail indications, filenames involved, and access control or flow control rules invoked.

    Application servers must log all relevant log data that pertains to the application server.  Examples of relevant data include, but are not limited to, Java Virtual Machine (JVM) activity, HTTPD/Web server activity, and application server-related system process activity.
  "
  desc  'rationale', ''
  desc  'check', "
    At the command prompt, run the following:

    # xmllint --xpath '/Server/Service/Engine/Host/Valve[@className=\"org.apache.catalina.valves.AccessLogValve\"]/@pattern' /usr/lib/loginsight/application/3rd_party/apache-tomcat/conf/server.xml

    Example result:

    pattern=\"%h %{X-Forwarded-For}i %l %u %t &quot;%r&quot; %s %b &quot;%{User-Agent}i&quot;\"

    Required elements:

    %h %{X-Forwarded-For}i %l %t %u &quot;%r&quot; %s %b

    If the log pattern does not contain the required elements in any order, this is a finding.
  "
  desc 'fix', "
    Navigate to and open:

    /usr/lib/loginsight/application/etc/3rd_config/server.xml

    Inside the <Host> node, find the \"AccessLogValve\" <Valve> node and replace the \"pattern\" element as follows:

    pattern=\"%h %{X-Forwarded-For}i %l %u %t &quot;%r&quot; %s %b &quot;%{User-Agent}i&quot;\"

    Restart the service with the following command:

    # systemctl restart loginsight.service

    Note: The configuration in \"/usr/lib/loginsight/application/3rd_party/apache-tomcat/conf/server.xml\" is generated when the service restarts based on the contents of the \"/usr/lib/loginsight/application/etc/3rd_config/server.xml\" file.
  "
  impact 0.5
  tag severity: 'medium'
  tag gtitle: 'SRG-APP-000095-AS-000056'
  tag satisfies: ['SRG-APP-000016-AS-000013', 'SRG-APP-000080-AS-000045', 'SRG-APP-000089-AS-000050', 'SRG-APP-000090-AS-000051', 'SRG-APP-000091-AS-000052', 'SRG-APP-000096-AS-000059', 'SRG-APP-000097-AS-000060', 'SRG-APP-000098-AS-000061', 'SRG-APP-000099-AS-000062', 'SRG-APP-000100-AS-000063', 'SRG-APP-000343-AS-000030', 'SRG-APP-000375-AS-000211', 'SRG-APP-000495-AS-000220', 'SRG-APP-000499-AS-000224', 'SRG-APP-000503-AS-000228', 'SRG-APP-000505-AS-000230', 'SRG-APP-000506-AS-000231']
  tag gid: 'V-VCFT-9X-000014'
  tag rid: 'SV-VCFT-9X-000014'
  tag stig_id: 'VCFT-9X-000014'
  tag cci: ['CCI-000067', 'CCI-000130', 'CCI-000131', 'CCI-000132', 'CCI-000133', 'CCI-000134', 'CCI-000166', 'CCI-000169', 'CCI-000171', 'CCI-000172', 'CCI-001487', 'CCI-001889', 'CCI-002234']
  tag nist: ['AC-17 (1)', 'AC-6 (9)', 'AU-10', 'AU-12 a', 'AU-12 b', 'AU-12 c', 'AU-3 a', 'AU-3 b', 'AU-3 c', 'AU-3 d', 'AU-3 e', 'AU-3 f', 'AU-8 b']

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

  describe "Checking for at least one AccessLogValve entry (count: #{count})" do
    subject { count }
    it { should > 0 }
  end
end
