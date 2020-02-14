control "VCFL-67-000021" do
  title "vSphere Client must set URIEncoding to UTF-8."
  desc  "Invalid user input occurs when a user inserts data or characters into
a hosted application's data entry field and the hosted application is
unprepared to process that data. This results in unanticipated application
behavior, potentially leading to an application compromise. Invalid user input
is one of the primary methods employed when attempting to compromise an
application.

    An attacker can also enter Unicode characters into hosted applications in
an effort to break out of the document home or root home directory or to bypass
security checks. vSphere Client must be configured to use a consistent
character set via the URIEncoding attribute on the Connector nodes."
  impact 0.5
  tag severity: "CAT II"
  tag gtitle: "SRG-APP-000251-WSR-000157"
  tag gid: nil
  tag rid: "VCFL-67-000021"
  tag stig_id: "VCFL-67-000021"
  tag cci: "CCI-001310"
  tag nist: ["SI-10", "Rev_4"]
  desc 'check', "At the command prompt, execute the following command:

# xmllint --format --xpath '/Server/Service/Connector/@URIEncoding'
/usr/lib/vmware-vsphere-client/server/configuration/tomcat-server.xml

Expected result:

URIEncoding=\"UTF-8\" URIEncoding=\"UTF-8\"r

If the output does not match the expected result, this is a finding."
  desc 'fix', "Navigate to and open
/usr/lib/vmware-vsphere-client/server/configuration/tomcat-server.xml

Configure each <Connector> node with the following:

URIEncoding=\"UTF-8\""

  begin
    vcui_conf = xml('/usr/lib/vmware-vsphere-client/server/configuration/tomcat-server.xml')

      if vcui_conf['Server/Service/Connector/attribute::URIEncoding'].is_a?(Array)
        vcui_conf['Server/Service/Connector/attribute::URIEncoding'].each do |x|
          describe x do
            it { should eq "UTF-8" }
          end
        end
      else
        describe xml(vcui_conf['Server/Service/Connector/attribute::URIEncoding']) do
          it { should eq "UTF-8" }
        end
      end
  end

end