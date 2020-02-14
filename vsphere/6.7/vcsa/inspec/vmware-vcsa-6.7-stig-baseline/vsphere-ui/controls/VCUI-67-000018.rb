control "VCUI-67-000018" do
  title "vSphere UI must limit the number of allowed connections."
  desc  "Limiting the number of established connections is a basic DoS
protection and a best practice. Servers where the limit is too high or
unlimited can potentiall run out of system resources and negatively affect
system availability."
  impact 0.5
  tag severity: "CAT II"
  tag gtitle: nil
  tag gid: nil
  tag rid: "VCUI-67-000018"
  tag stig_id: "VCUI-67-000018"
  tag cci: nil
  tag nist: nil
  desc 'check', "At the command prompt, execute the following command:

# xmllint --format /usr/lib/vmware-vsphere-ui/server/conf/server.xml | sed '2
s/xmlns=\".*\"//g' |  xmllint --xpath
'/Server/Service/Connector[@port=\"${http.port}\"]/@acceptCount' -

Expected result:

acceptCount=\"300\"

If the output does not match the expected result, this is a finding"
  desc 'fix', "Navigate to and open
/usr/lib/vmware-vsphere-ui/server/conf/server.xml

Navigate to the <Connector> configured with port=\"${http.port}\". Add or
change the folllowing value:

acceptCount=\"300\""
 
  describe xml('/usr/lib/vmware-vsphere-ui/server/conf/server.xml') do
    its(['Server/Service/Connector[@port=\'${http.port}\']/@acceptCount']) { should cmp '300'}
  end

end