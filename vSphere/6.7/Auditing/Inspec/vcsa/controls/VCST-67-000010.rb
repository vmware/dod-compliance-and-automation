control "VCST-67-000010" do
  title "The Security Token Service must not be configured with unsupported
realms."
  desc  "The Security Token Service performs user authentication at the
application level and not through Tomcat. In the name of eliminating
unnecessary features and to ensure that the Security Token Service remains in
it's shipping state, the lack of a UserDatabaseRealm configuration must be
confirmed."
  impact 0.5
  tag severity: "CAT II"
  tag gtitle: "SRG-APP-000141-WSR-000015"
  tag gid: nil
  tag rid: "VCST-67-000010"
  tag stig_id: "VCST-67-000010"
  tag fix_id: nil
  tag cci: "CCI-000381"
  tag nist: ["CM-7 a", "Rev_4"]
  tag false_negatives: nil
  tag false_positives: nil
  tag documentable: nil
  tag mitigations: nil
  tag severity_override_guidance: nil
  tag potential_impacts: nil
  tag third_party_tools: nil
  tag mitigation_controls: nil
  tag responsibility: nil
  tag ia_controls: "CM-7 a"
  tag check: "At the command prompt, execute the following command:

# grep UserDatabaseRealm /usr/lib/vmware-sso/vmware-sts/conf/server.xml

If the command produces any output, this is a finding."
  tag fix: "Navigate to and open /usr/lib/vmware-sso/vmware-sts/conf/server.xml
. Remove the <Realm> node returned in the check."
end

