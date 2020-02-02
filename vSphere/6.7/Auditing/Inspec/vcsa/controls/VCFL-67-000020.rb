control "VCFL-67-000020" do
  title "vSphere Client must limit the number of allowed connections."
  desc  "Limiting the number of established connections to Sphere Client is a
basic DoS protection. Servers where the limit is too high or unlimited can
potentially run out of system resources and negatively affect system
availability."
  impact 0.5
  tag severity: "CAT II"
  tag gtitle: "SRG-APP-000246-WSR-000149"
  tag gid: nil
  tag rid: "VCFL-67-000020"
  tag stig_id: "VCFL-67-000020"
  tag fix_id: nil
  tag cci: "CCI-001094"
  tag nist: ["SC-5 (1)", "Rev_4"]
  tag false_negatives: nil
  tag false_positives: nil
  tag documentable: nil
  tag mitigations: nil
  tag severity_override_guidance: nil
  tag potential_impacts: nil
  tag third_party_tools: nil
  tag mitigation_controls: nil
  tag responsibility: nil
  tag ia_controls: "SC-5 (1)"
  tag check: "At the command prompt, execute the following command:

# xmllint --format --xpath '/Server/Service/Connector/@acceptCount'
/usr/lib/vmware-vsphere-client/server/configuration/tomcat-server.xml

Expected result:

acceptCount=\"300\" acceptCount=\"300\"

If the output does not match the expected result, this is a finding."
  tag fix: "Navigate to and open
/usr/lib/vmware-vsphere-client/server/configuration/tomcat-server.xml

Configure each <Connector> node with the following:

acceptCount=\"300\""

  describe xml('/usr/lib/vmware-vsphere-client/server/configuration/tomcat-server.xml') do
    its(['Server/Service/Connector/@acceptCount']) { should cmp '300'}
  end

end