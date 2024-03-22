control 'VRLT-8X-000131' do
  title 'The VMware Aria Operations for Logs tc Server must ensure that Connectors are secured for connectors that do not redirect to a secure port.'
  desc  'The unencrypted HTTP protocol does not protect data from interception or alteration which can subject users to eavesdropping, tracking, and the modification of received data. To secure an HTTP connector, both the secure and scheme flags must be set.'
  desc  'rationale', ''
  desc  'check', "
    At the command prompt, run the following commands:

    # xmllint --xpath \"//Connector[not(@scheme)] | //Connector[@scheme != 'https']\" /usr/lib/loginsight/application/3rd_party/apache-tomcat/conf/server.xml
    # xmllint --xpath \"//Connector[not(@secure)] | //Connector[@secure!= 'true']\" /usr/lib/loginsight/application/3rd_party/apache-tomcat/conf/server.xml

    Examine each <Connector/> element.

    For each connector that is not a redirect to a secure port, verify the secure= flag is set to \"true\" and the scheme= flag is set to \"https\".

    If the secure flag is not set to \"true\" and/or the scheme flag is not set to \"https\" for each HTTP connector element, this is a finding.
  "
  desc 'fix', "
    Edit the /usr/lib/loginsight/application/etc/3rd_config/server.xml file.

    Locate each <Connector/> element that is not a redirect to a secure port and is lacking a secure setting.

    Set or add scheme=\"https\" and secure=\"true\" for each connector element.

    EXAMPLE:
    <Connector port=\"443\" protocol=\"org.apache.coyote.http11.Http11NioProtocol\" SSLEnabled=\"true\"
    maxThreads=\"150\" scheme=\"https\" secure=\"true\".../>

    Restart the service:
    # systemctl restart loginsight.service
  "
  impact 0.5
  tag severity: 'medium'
  tag gtitle: 'SRG-APP-000033-AS-000024'
  tag gid: 'V-VRLT-8X-000131'
  tag rid: 'SV-VRLT-8X-000131'
  tag stig_id: 'VRLT-8X-000131'
  tag cci: ['CCI-000213']
  tag nist: ['AC-3']

  # Open server.xml file
  xmlconf = xml("#{input('catalinaBase')}/conf/server.xml")

  # Loop through given list of secure ports
  input('securePorts').each do |sp|
    conn = xmlconf["//Connector[@port='#{sp}']/"].count
    if conn > 0
      describe "Checking for secure flags on connectors using secure port #{sp}" do
        subject { xmlconf["//Connector[@port='#{sp}']/@secure"] }
        it { should eq ['true'] }
      end
      describe "Checking for scheme flags on connectors using secure port #{sp}" do
        subject { xmlconf["//Connector[@port='#{sp}']/@scheme"] }
        it { should eq ['https'] }
      end
    else
      describe "Checking for connectors bound to secure port #{sp}" do
        skip "No connectors bound to secure port #{sp}"
      end
    end
  end
end
