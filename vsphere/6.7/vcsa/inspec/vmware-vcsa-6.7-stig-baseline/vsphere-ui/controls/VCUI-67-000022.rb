control 'VCUI-67-000022' do
  title 'vSphere UI must be configured to hide the server version.'
  desc  "Web servers will often display error messages to client users with
enough information to aid in the debugging of the error. The information given
back in error messages may display the web server type, version, patches
installed, plug-ins and modules installed, type of code being used by the
hosted application, and any backends being used for data storage. This
information could be used by an attacker to blueprint what type of attacks
might be successful. Therefore, vSphere UI must be configured to hide the
server version at all times."
  desc  'rationale', ''
  desc  'check', "
    At the command prompt, execute the following command:

    # xmllint --format /usr/lib/vmware-vsphere-ui/server/conf/server.xml | sed
'2 s/xmlns=\".*\"//g' |  xmllint --xpath
'/Server/Service/Connector[@port=\"${http.port}\"]/@server' -

    Expected result:

    server=\"Anonymous\"

    If the output does not match the expected result, this is a finding.
  "
  desc 'fix', "
    Navigate to and open /usr/lib/vmware-vsphere-ui/server/conf/server.xml.

    Navigate to each of the <Connector> nodes.

    Configure each <Connector> node with 'server=\"Anonymous\"'.
  "
  impact 0.5
  tag severity: 'medium'
  tag gtitle: 'SRG-APP-000266-WSR-000159'
  tag gid: 'V-239703'
  tag rid: 'SV-239703r679215_rule'
  tag stig_id: 'VCUI-67-000022'
  tag fix_id: 'F-42895r679214_fix'
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
