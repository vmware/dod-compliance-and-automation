control "VCEM-67-000004" do
  title "ESX Agent Manager must protect cookies from XSS."
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
  tag rid: "VCEM-67-000004"
  tag stig_id: "VCEM-67-000004"
  tag cci: "CCI-000054"
  tag nist: ["AC-10", "Rev_4"]
  desc 'check', "At the command prompt, execute the following command:

# xmllint --format /usr/lib/vmware-eam/web/webapps/eam/WEB-INF/web.xml | sed
's/xmlns=\".*\"//g' | xmllint --xpath
'/web-app/session-config/cookie-config/http-only' -

Expected result:

<http-only>true</http-only>

If the output does not match the expected result, this is a finding."
  desc 'fix', "Navigate to and open
/usr/lib/vmware-eam/web/webapps/eam/WEB-INF/web.xml

Navigate to the <session-config> node and configure it as follows.

    <session-config>
      <cookie-config>
         <http-only>true</http-only>
         <secure>true</secure>
      </cookie-config>
      <session-timeout>30</session-timeout>
   </session-config>"

  describe xml('/usr/lib/vmware-eam/web/webapps/eam/WEB-INF/web.xml') do
    its(['/web-app/session-config/cookie-config/http-only']) { should cmp 'true' }
  end

end

