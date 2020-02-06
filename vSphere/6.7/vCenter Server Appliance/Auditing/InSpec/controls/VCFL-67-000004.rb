control "VCFL-67-000004" do
  title "vSphere Client  must protect cookies from XSS."
  desc  "Cookies are a common way to save session state over the HTTP(S)
protocol. If an attacker can compromise session data stored in a cookie, they
are better able to launch an attack against the server and its applications.
When you tag a cookie with the HttpOnly flag, it tells the browser that this
particular cookie should only be accessed by the originating server. Any
attempt to access the cookie from client script is strictly forbidden."
  impact 0.5
  tag severity: "CAT II"
  tag gtitle: "SRG-APP-000001-WSR-000002"
  tag gid: nil
  tag rid: "VCFL-67-000004"
  tag stig_id: "VCFL-67-000004"
  tag fix_id: nil
  tag cci: "CCI-000054"
  tag nist: ["AC-10", "Rev_4"]
  tag false_negatives: nil
  tag false_positives: nil
  tag documentable: nil
  tag mitigations: nil
  tag severity_override_guidance: nil
  tag potential_impacts: nil
  tag third_party_tools: nil
  tag mitigation_controls: nil
  tag responsibility: nil
  tag ia_controls: "AC-10"
  tag check: "At the command prompt, execute the following command:

# xmllint --xpath '/Context/@useHttpOnly'
/usr/lib/vmware-vsphere-client/server/configuration/context.xml

Expected result:

useHttpOnly=\"true\"

If the output does not match the expected result, this is a finding."
  tag fix: "Navigate to and open
/usr/lib/vmware-vsphere-client/server/configuration/context.xml

Configure the <Context> node as follows:

<Context useHttpOnly=\"true\">"

  describe xml('/usr/lib/vmware-vsphere-client/server/configuration/context.xml') do
    its(['Context/attribute::useHttpOnly']) { should eq ['true'] }
  end

end