control "VCLD-67-000016" do
  title "VAMI must only contain services and functions necessary for operation."
  desc  "A web server can provide many features, services, and processes. Some
of these may be deemed unnecessary or too unsecure to run on a production DoD
system.

    The web server must provide the capability to disable, uninstall, or
deactivate functionality and services that are deemed to be non-essential to
the web server mission or can adversely impact server performance."
  tag component: "vami"
  tag severity: nil
  tag gtitle: "SRG-APP-000141-WSR-000075"
  tag gid: nil
  tag rid: "VCLD-67-000016"
  tag stig_id: "VCLD-67-000016"
  tag cci: "CCI-000381"
  tag nist: ["CM-7 a", "Rev_4"]
  desc 'check', "At the command prompt, execute the following command:

cat /opt/vmware/etc/lighttpd/lighttpd.conf | awk '/server\\.modules/,/\\)/'

If does not match the below output, this is a finding.

server.modules = (
  \"mod_access\",
  \"mod_accesslog\",
  \"mod_proxy\",
  \"mod_cgi\",
  \"mod_rewrite\",
)
server.modules += ( \"mod_magnet\" )
"
  desc 'fix', "Navigate to and open /opt/vmware/etc/lighttpd/lighttpd.conf

Navigate to and configure the \"server.modules\" section and replace it with
the following:

server.modules = (
  \"mod_access\",
  \"mod_accesslog\",
  \"mod_proxy\",
  \"mod_cgi\",
  \"mod_rewrite\",
)
server.modules += ( \"mod_magnet\" )"

  describe command("cat /opt/vmware/etc/lighttpd/lighttpd.conf | awk '/server\.modules/,/\)/'") do
    its ('stdout') { should match "server.modules = (\n  \"mod_access\",\n  \"mod_accesslog\",\n  \"mod_proxy\",\n  \"mod_cgi\",\n  \"mod_rewrite\",\n)\nserver.modules += ( \"mod_magnet\" )\n"  }
  end

end

