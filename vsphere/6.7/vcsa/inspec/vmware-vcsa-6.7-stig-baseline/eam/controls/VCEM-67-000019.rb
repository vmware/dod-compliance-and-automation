control "VCEM-67-000019" do
  title "ESX Agent Manager must limit the number of allowed connections."
  desc  "Limiting the number of established connections to the ESX Agent
Manager is a basic DoS protection. Servers where the limit is too high or
unlimited can potentially run out of system resources and negatively affect
system availability."
  impact 0.5
  tag severity: "CAT II"
  tag gtitle: "SRG-APP-000246-WSR-000149"
  tag gid: nil
  tag rid: "VCEM-67-000019"
  tag stig_id: "VCEM-67-000019"
  tag cci: "CCI-001094"
  tag nist: ["SC-5 (1)", "Rev_4"]
  desc 'check', "At the command prompt, execute the following command:

# xmllint --xpath '/Server/Service/Connector/@acceptCount'
/usr/lib/vmware-eam/web/conf/server.xml

Expected result:

acceptCount=\"300\"

If the output does not match the expected result, this is a finding"
  desc 'fix', "Navigate to and open /usr/lib/vmware-eam/web/conf/server.xml

Configure the <Connector> node with the value:

acceptCount=\"300\""

  describe xml('/usr/lib/vmware-eam/web/conf/server.xml') do
    its(['Server/Service/Connector/@acceptCount']) { should cmp '300'}
  end

end

