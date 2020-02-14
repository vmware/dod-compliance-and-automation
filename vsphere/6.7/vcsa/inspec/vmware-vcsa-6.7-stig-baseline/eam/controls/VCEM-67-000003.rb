control "VCEM-67-000003" do
  title "ESX Agent Manager must limit the maximum size of a POST request."
  desc  "The 'maxPostSize' value is the maximum size in bytes of the POST which
will be handled by the container FORM URL parameter parsing. Limit its size to
reduce exposure to a DOS attack. If 'maxPostSize' is not set, the default value
of 2097152 (2MB) is used. ESX Agent Manager is configured in it's shipping
state to not set a value for 'maxPostSize'."
  impact 0.5
  tag severity: "CAT II"
  tag gtitle: "SRG-APP-000001-WSR-000001"
  tag gid: nil
  tag rid: "VCEM-67-000003"
  tag stig_id: "VCEM-67-000003"
  tag cci: "CCI-000054"
  tag nist: ["AC-10", "Rev_4"]
  desc 'check', "At the command prompt, execute the following command:

# xmllint --xpath
'/Server/Service/Connector[@port=\"${bio-custom.http.port}\"]/@maxPostSize'
/usr/lib/vmware-eam/web/conf/server.xml

Expected result:

XPath set is empty

If the output does not match the expected result, this is a finding."
  desc 'fix', "Navigate to and open /usr/lib/vmware-eam/web/conf/server.xml

Remove any configuration for 'maxPostSize' from the <Connector> node."

  describe xml('/usr/lib/vmware-eam/web/conf/server.xml') do
    its('Server/Service/Connector/attribute::maxPostSize') { should eq [] }
  end

end

