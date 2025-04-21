control 'VCLU-70-000023' do
  title 'Lookup Service must be configured to hide the server version.'
  desc 'Web servers will often display error messages to client users, including enough information to aid in the debugging of the error. The information given back in error messages may display the web server type, version, patches installed, plug-ins and modules installed, type of code being used by the hosted application, and any backends being used for data storage.

This information could be used by an attacker to blueprint what type of attacks might be successful. Therefore, Lookup Service must be configured to hide the server version at all times.'
  desc 'check', %q(At the command prompt, run the following command:

# xmllint --xpath '/Server/Service/Connector[@port="${bio-custom.http.port}"]/@server' /usr/lib/vmware-lookupsvc/conf/server.xml

Expected result:

server="Anonymous"

If the output does not match the expected result, this is a finding.)
  desc 'fix', %q(Navigate to and open:

/usr/lib/vmware-lookupsvc/conf/server.xml

Navigate to each of the <Connector> nodes.

Configure each <Connector> node with 'server="Anonymous"'.

Restart the service with the following command:

# vmon-cli --restart lookupsvc)
  impact 0.5
  tag check_id: 'C-60403r888773_chk'
  tag severity: 'medium'
  tag gid: 'V-256728'
  tag rid: 'SV-256728r888775_rule'
  tag stig_id: 'VCLU-70-000023'
  tag gtitle: 'SRG-APP-000266-WSR-000159'
  tag fix_id: 'F-60346r888774_fix'
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
