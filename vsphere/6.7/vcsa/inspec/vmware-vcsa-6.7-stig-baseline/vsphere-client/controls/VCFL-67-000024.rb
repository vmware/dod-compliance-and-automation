control "VCFL-67-000024" do
  title "vSphere Client must be configured to show error pages with minimal
information."
  desc  "Web servers will often display error messages to client users
displaying enough information to aid in the debugging of the error. The
information given back in error messages may display the web server type,
version, patches installed, plug-ins and modules installed, type of code being
used by the hosted application, and any backends being used for data storage.
This information could be used by an attacker to blueprint what type of attacks
might be successful. As such, vSphere Client must be configured to not show
server version information in error messages."
  impact 0.5
  tag severity: "CAT II"
  tag gtitle: "SRG-APP-000266-WSR-000159"
  tag gid: nil
  tag rid: "VCFL-67-000024"
  tag stig_id: "VCFL-67-000024"
  tag cci: "CCI-001312"
  tag nist: ["SI-11 a", "Rev_4"]
  desc 'check', "At the command prompt, execute the following command:

# xmllint --format --xpath '/Server/Service/Connector/@server'
/usr/lib/vmware-vsphere-client/server/configuration/tomcat-server.xml

Expected result:

server=\"Anonymous\" server=\"Anonymous\"

If the output does not match the expected result, this is a finding."
  desc 'fix', "Navigate to and open
/usr/lib/vmware-vsphere-client/server/configuration/tomcat-server.xml

Configure each <Connector> node with the following:

server=\"Anonymous\""

  begin
    vcui_conf = xml('/usr/lib/vmware-vsphere-client/server/configuration/tomcat-server.xml')

      if vcui_conf['Server/Service/Connector/attribute::server'].is_a?(Array)
        vcui_conf['Server/Service/Connector/attribute::server'].each do |x|
          describe x do
            it { should eq "Anonymous" }
          end
        end
      else
        describe xml(vcui_conf['Server/Service/Connector/attribute::server']) do
          it { should eq "Anonymous" }
        end
      end
  end

end