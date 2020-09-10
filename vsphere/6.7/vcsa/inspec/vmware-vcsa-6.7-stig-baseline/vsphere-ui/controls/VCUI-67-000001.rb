control "VCUI-67-000001" do
  title "vSphere UI must limit the amount of time that each TCP connection is
kept alive."
  desc  "Denial of Service is one threat against web servers.  Many DoS attacks
attempt to consume web server resources in such a way that no more resources
are available to satisfy legitimate requests.

    In Tomcat, the 'connectionTimeout' attribute sets the number of
milliseconds the server will wait after accepting a connection for the request
URI line to be presented. This timeout will also be used when reading the
request body (if any). This prevents idle sockets that are not sending HTTP
requests from consuming system resources and potentially denying new
connections."
  impact 0.5
  tag severity: "CAT II"
  tag gtitle: "SRG-APP-000001-WSR-000001"
  tag rid: "VCUI-67-000001"
  tag stig_id: "VCUI-67-000001"
  tag cci: "CCI-000054"
  tag nist: ["AC-10", "Rev_4"]
  desc 'check', "At the command prompt, execute the following command:

# xmllint --format /usr/lib/vmware-vsphere-ui/server/conf/server.xml | sed '2
s/xmlns=\".*\"//g' |  xmllint --xpath
'/Server/Service/Connector[@port=\"${http.port}\"]/@connectionTimeout' -

Expected result:

connectionTimeout=\"20000\"

If the output does not match the expected result, this is a finding"
  desc 'fix', "Navigate to and open
/usr/lib/vmware-vsphere-ui/server/conf/server.xml

Configure the http <Connector> node with the value 'connectionTimeout=\"20000\"'

Ex:<Connector .. connectionTimeout=\"20000\" ..>"

  begin
    vcui_conf = xml('/usr/lib/vmware-vsphere-ui/server/conf/server.xml')

      if vcui_conf['Server/Service/Connector/attribute::connectionTimeout'].is_a?(Array)
        vcui_conf['Server/Service/Connector/attribute::connectionTimeout'].each do |x|
          describe x do
            it { should eq "20000" }
          end
        end
      else
        describe xml(vcui_conf['Server/Service/Connector/attribute::connectionTimeout']) do
          it { should eq "20000" }
        end
      end
  end
  
end
