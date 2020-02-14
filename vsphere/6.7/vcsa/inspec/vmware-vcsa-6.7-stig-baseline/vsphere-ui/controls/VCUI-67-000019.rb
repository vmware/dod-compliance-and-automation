control "VCUI-67-000019" do
  title "vSphere UI must set URIEncoding to UTF-8."
  desc  "Invalid user input occurs when a user inserts data or characters into
a hosted application's data entry field and the hosted application is
unprepared to process that data. This results in unanticipated application
behavior, potentially leading to an application compromise. Invalid user input
is one of the primary methods employed when attempting to compromise an
application.

    An attacker can also enter Unicode characters into hosted applications in
an effort to break out of the document home or root home directory or to bypass
security checks. vSphere UI must be configured to use a consistent character
set via the URIEncoding attribute on the Connector nodes."
  impact 0.5
  tag severity: "CAT II"
  tag gtitle: nil
  tag gid: nil
  tag rid: "VCUI-67-000019"
  tag stig_id: "VCUI-67-000019"
  tag cci: nil
  tag nist: nil
  desc 'check', "At the command prompt, execute the following command:

# xmllint --format /usr/lib/vmware-vsphere-ui/server/conf/server.xml | sed '2
s/xmlns=\".*\"//g' |  xmllint --xpath
'/Server/Service/Connector[@port=\"${http.port}\"]/@URIEncoding' -

Expected result:

URIEncoding=\"UTF-8\"

If the output does not match the expected result, this is a finding"
  desc 'fix', "Navigate to and open
/usr/lib/vmware-vsphere-ui/server/conf/server.xml

Navigate to each of the <Connector> nodes.

Configure each <Connector> node with the value 'URIEncoding=\"UTF-8\"'."

  begin
    vcui_conf = xml('/usr/lib/vmware-vsphere-ui/server/conf/server.xml')

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