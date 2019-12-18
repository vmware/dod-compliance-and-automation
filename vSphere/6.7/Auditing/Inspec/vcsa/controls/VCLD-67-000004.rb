control "VCLD-67-000004" do
  title "VAMI must be configured to use mod_accesslog."
  desc  "Remote access can be exploited by an attacker to compromise the
server.  By recording all remote access activities, it will be possible to
determine the attacker's location, intent, and degree of success.

    Lighttpd uses the mod_accesslog module to share information with external
monitoring systems.
  "
  tag component: "vami"
  tag severity: nil
  tag gtitle: "SRG-APP-000016-WSR-000005"
  tag gid: nil
  tag rid: "VCLD-67-000004"
  tag stig_id: "VCLD-67-000004"
  tag fix_id: nil
  tag cci: "CCI-000067"
  tag nist: ["AC-17 (1)", "Rev_4"]
  tag false_negatives: nil
  tag false_positives: nil
  tag documentable: nil
  tag mitigations: nil
  tag severity_override_guidance: nil
  tag potential_impacts: nil
  tag third_party_tools: nil
  tag mitigation_controls: nil
  tag responsibility: nil
  tag ia_controls: "AC-17 (1)"
  tag check: "At the command prompt, execute the following command:

cat /opt/vmware/etc/lighttpd/lighttpd.conf | awk '/server\\.modules/,/\\)/'

If the value \"mod_accesslog\" is not listed, this is a finding."
  tag fix: "Navigate to and open /opt/vmware/etc/lighttpd/lighttpd.conf

Navigate to and configure the \"server.modules\" section with the following
value:

mod_accesslog"

  describe command("cat /opt/vmware/etc/lighttpd/lighttpd.conf | awk '/server\.modules/,/\)/'") do
    its ('stdout') { should match "server.modules = (\n  \"mod_access\",\n  \"mod_accesslog\",\n  \"mod_proxy\",\n  \"mod_cgi\",\n  \"mod_rewrite\",\n)\nserver.modules += ( \"mod_magnet\" )\n"  }
  end

end

