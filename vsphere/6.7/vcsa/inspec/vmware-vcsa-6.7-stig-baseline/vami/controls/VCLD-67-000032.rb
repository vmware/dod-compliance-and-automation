control "VCLD-67-000032" do
  title "VAMI must be configured to utilize the Common Information Model Object
Manager. "
  desc  "Remote access to the web server is any access that communicates
through an external, non-organization-controlled network. Remote access can be
used to access hosted applications or to perform management functions.

    A web server can be accessed remotely and must be able to enforce remote
access policy requirements or work in conjunction with enterprise tools
designed to enforce policy requirements.

    VAMI uses CIMOM to Authenticate the sysadmin and to enforce
    policy requirements."
  tag component: "vami"
  tag severity: nil
  tag gtitle: "SRG-APP-000315-WSR-000003"
  tag gid: nil
  tag rid: "VCLD-67-000032"
  tag stig_id: "VCLD-67-000032"
  tag cci: "CCI-002314"
  tag nist: ["AC-17 (1)", "Rev_4"]
  desc 'check', "At the command prompt, execute the following command:

cat /opt/vmware/etc/lighttpd/lighttpd.conf | awk '/cimom/,/}/'

Note:  The return value should produce the following output:

$HTTP[\"url\"] =~ \"^/cimom\" {
    proxy.server = ( \"\" =>
                    ((
                      \"host\" => \"127.0.0.1\",
                      \"port\" => \"5488\"
                    ))
                   )
}

If the return value does not match the above output, this is a finding."
  desc 'fix', "Navigate to and open /opt/vmware/etc/lighttpd/lighttpd.conf

Configure the lighttpd.conf with the following:

$HTTP[\"url\"] =~ \"^/cimom\" {
    proxy.server = ( \"\" =>
                    ((
                      \"host\" => \"127.0.0.1\",
                      \"port\" => \"5488\"
                    ))
                   )
}"

describe command("cat /opt/vmware/etc/lighttpd/lighttpd.conf | awk '/cimom/,/}/'") do
    its ('stdout') { should match "$HTTP[\"url\"] =~ \"^/cimom\" {\n    proxy.server = ( \"\" =>\n                    ((\n                      \"host\" => \"127.0.0.1\",\n                      \"port\" => \"5488\"\n                    ))\n                   )\n}\n" }
  end

end

