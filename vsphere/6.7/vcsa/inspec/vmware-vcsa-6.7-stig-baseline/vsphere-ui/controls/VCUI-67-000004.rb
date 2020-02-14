control "VCUI-67-000004" do
  title "vSphere UI must protect cookies from XSS."
  desc  "Cookies are a common way to save session state over the HTTP(S)
protocol. If an attacker can compromise session data stored in a cookie, they
are better able to launch an attack against the server and its applications.
When you tag a cookie with the HttpOnly flag, it tells the browser that this
particular cookie should only be accessed by the originating server. Any
attempt to access the cookie from client script is strictly forbidden."
  impact 0.5
  tag severity: "CAT II"
  tag gtitle: "SRG-APP-000266-WSR-000159"
  tag gid: nil
  tag rid: "VCUI-67-000004"
  tag stig_id: "VCUI-67-000004"
  tag cci: "CCI-001312"
  tag nist: ["SI-11 a", "Rev_4"]
  desc 'check', "At the command prompt, execute the following command:

# xmllint --format /usr/lib/vmware-vsphere-ui/server/conf/context.xml | xmllint
--xpath '/Context/@useHttpOnly' -

Expected result:

useHttpOnly=\"true\"

If the output does not match the expected result, this is a finding."
  desc 'fix', "Navigate to and open
/usr/lib/vmware-vsphere-ui/server/conf/context.xml . Add the following
configuration to the <Context> node:

useHttpOnly=\"true\"

Ex:

<Context useHttpOnly=\"true\" sessionCookieName=\"VSPHERE-UI-JSESSIONID\"
sessionCookiePath=\"/ui\">"

  describe xml('/usr/lib/vmware-vsphere-ui/server/conf/context.xml') do
    its(['Context/attribute::useHttpOnly']) { should eq ['true'] }
  end

end