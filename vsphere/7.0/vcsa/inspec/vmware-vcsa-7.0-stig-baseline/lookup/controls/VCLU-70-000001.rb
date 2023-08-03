control 'VCLU-70-000001' do
  title 'Lookup Service must limit the amount of time that each Transport Control Protocol (TCP) connection is kept alive.'
  desc 'Denial of service (DoS) is one threat against web servers. Many DoS attacks attempt to consume web server resources in such a way that no more resources are available to satisfy legitimate requests.

In Tomcat, the "connectionTimeout" attribute sets the number of milliseconds the server will wait after accepting a connection for the request Uniform Resource Identifier (URI) line to be presented. This timeout will also be used when reading the request body (if any). This prevents idle sockets that are not sending HTTP requests from consuming system resources and potentially denying new connections.'
  desc 'check', %q(At the command prompt, run the following command:

# xmllint --xpath '/Server/Service/Connector[@port="${bio-custom.http.port}"]/@connectionTimeout' /usr/lib/vmware-lookupsvc/conf/server.xml

Expected result:

connectionTimeout="60000"

If the output does not match the expected result, this is a finding.)
  desc 'fix', 'Navigate to and open:

/usr/lib/vmware-lookupsvc/conf/server.xml

Configure the <Connector> node with the value:

connectionTimeout="60000"

Example:

<Connector .. connectionTimeout="60000" ..>

Restart the service with the following command:

# vmon-cli --restart lookupsvc'
  impact 0.5
  tag check_id: 'C-60381r888707_chk'
  tag severity: 'medium'
  tag gid: 'V-256706'
  tag rid: 'SV-256706r888709_rule'
  tag stig_id: 'VCLU-70-000001'
  tag gtitle: 'SRG-APP-000001-WSR-000001'
  tag fix_id: 'F-60324r888708_fix'
  tag cci: ['CCI-000054']
  tag nist: ['AC-10']

  begin
    xmlconf = xml("#{input('serverXmlPath')}")
    if xmlconf['/Server/Service/Connector[@port="${bio-custom.http.port}"]/attribute::connectionTimeout'].is_a?(Array)
      xmlconf['/Server/Service/Connector[@port="${bio-custom.http.port}"]/attribute::connectionTimeout'].each do |x|
        describe x do
          it { should eq "#{input('connectionTimeout')}" }
        end
      end
    else
      describe xml(xmlconf['/Server/Service/Connector[@port="${bio-custom.http.port}"]/attribute::connectionTimeout']) do
        it { should eq "#{input('connectionTimeout')}" }
      end
    end
  end
end
