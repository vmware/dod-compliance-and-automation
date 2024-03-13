control 'WOAT-3X-000071' do
  title 'Workspace ONE Access must hide the server version.'
  desc  'Web servers will often display error messages to client users displaying enough information to aid in the debugging of the error. The information given back in error messages may display the web server type, version, patches installed, plug-ins and modules installed, type of code being used by the hosted application, and any backends being used for data storage. This information could be used by an attacker to blueprint what type of attacks might be successful.'
  desc  'rationale', ''
  desc  'check', "
    At the command prompt, execute the following command:

    # xmllint --xpath '/Server/Service/Connector/@server' /opt/vmware/horizon/workspace/conf/server.xml

    Expected result:

    server=\"Anonymous\"

    If the output of the command does not match the expected result, this is a finding.
  "
  desc 'fix', "
    Navigate to and open:

    /opt/vmware/horizon/workspace/conf/server.xml

    Configure each <Connector> node with the value:

    server=\"Anonymous\"
  "
  impact 0.5
  tag severity: 'medium'
  tag gtitle: 'SRG-APP-000266-WSR-000159'
  tag gid: 'V-WOAT-3X-000071'
  tag rid: 'SV-WOAT-3X-000071'
  tag stig_id: 'WOAT-3X-000071'
  tag cci: ['CCI-001312']
  tag nist: ['SI-11 a']

  begin
    xmlconf = xml("#{input('serverXmlPath')}")

    if xmlconf['Server/Service/Connector/attribute::server'].is_a?(Array)
      xmlconf['Server/Service/Connector/attribute::server'].each do |x|
        describe x do
          it { should eq "#{input('server')}" }
        end
      end
    else
      describe xml(xmlconf['Server/Service/Connector/attribute::server']) do
        it { should eq "#{input('server')}" }
      end
    end
  end
end
