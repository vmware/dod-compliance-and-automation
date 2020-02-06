control "VCEM-67-000020" do
  title "ESX Agent Manager must set URIEncoding to UTF-8."
  desc  "Invalid user input occurs when a user inserts data or characters into
a hosted application's data entry field and the hosted application is
unprepared to process that data. This results in unanticipated application
behavior, potentially leading to an application compromise. Invalid user input
is one of the primary methods employed when attempting to compromise an
application.

    An attacker can also enter Unicode characters into hosted applications in
an effort to break out of the document home or root home directory or to bypass
security checks. ESX Agent Manager must be configured to use a consistent
character set via the URIEncoding attribute on the Connector nodes."
  impact 0.5
  tag severity: "CAT II"
  tag gtitle: "SRG-APP-000251-WSR-000157"
  tag gid: nil
  tag rid: "VCEM-67-000020"
  tag stig_id: "VCEM-67-000020"
  tag fix_id: nil
  tag cci: "CCI-001310"
  tag nist: ["SI-10", "Rev_4"]
  tag false_negatives: nil
  tag false_positives: nil
  tag documentable: nil
  tag mitigations: nil
  tag severity_override_guidance: nil
  tag potential_impacts: nil
  tag third_party_tools: nil
  tag mitigation_controls: nil
  tag responsibility: nil
  tag ia_controls: "SI-10"
  tag check: "At the command prompt, execute the following command:

# xmllint --xpath '/Server/Service/Connector/@URIEncoding'
/usr/lib/vmware-eam/web/conf/server.xml

Expected result:

URIEncoding=\"UTF-8\"

If the output does not match the expected result, this is a finding"
  tag fix: "Navigate to and open /usr/lib/vmware-eam/web/conf/server.xml

Configure the <Connector> node with the value:

URIEncoding=\"UTF-8\""

  describe xml('/usr/lib/vmware-eam/web/conf/server.xml') do
    its(['Server/Service/Connector/@URIEncoding']) { should cmp 'UTF-8'}
  end

end