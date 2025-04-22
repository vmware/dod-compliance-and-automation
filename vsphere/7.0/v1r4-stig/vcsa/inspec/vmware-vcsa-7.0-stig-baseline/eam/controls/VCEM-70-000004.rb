control 'VCEM-70-000004' do
  title 'ESX Agent Manager must protect cookies from cross-site scripting (XSS).'
  desc 'Cookies are a common way to save session state over the HTTP(S) protocol. If attackers can compromise session data stored in a cookie, they are better able to launch an attack against the server and its applications. When a cookie is tagged with the "HttpOnly" flag, it tells the browser this particular cookie should only be accessed by the originating server. Any attempt to access the cookie from client script is strictly forbidden.

'
  desc 'check', %q(At the command prompt, run the following command:

# xmllint --format /usr/lib/vmware-eam/web/webapps/eam/WEB-INF/web.xml | sed 's/xmlns=".*"//g' | xmllint --xpath '/web-app/session-config/cookie-config/http-only' -

Expected result:

<http-only>true</http-only>

If the output does not match the expected result, this is a finding.)
  desc 'fix', 'Navigate to and open:

/usr/lib/vmware-eam/web/webapps/eam/WEB-INF/web.xml

Navigate to the <session-config> node and configure it as follows:

    <session-config>
      <cookie-config>
         <http-only>true</http-only>
         <secure>true</secure>
      </cookie-config>
      <session-timeout>30</session-timeout>
   </session-config>

Restart the service with the following command:

# vmon-cli --restart eam'
  impact 0.5
  tag check_id: 'C-60351r888582_chk'
  tag severity: 'medium'
  tag gid: 'V-256676'
  tag rid: 'SV-256676r888584_rule'
  tag stig_id: 'VCEM-70-000004'
  tag gtitle: 'SRG-APP-000001-WSR-000002'
  tag fix_id: 'F-60294r888583_fix'
  tag satisfies: ['SRG-APP-000001-WSR-000002', 'SRG-APP-000223-WSR-000011', 'SRG-APP-000439-WSR-000154', 'SRG-APP-000439-WSR-000155']
  tag cci: ['CCI-000054', 'CCI-001664', 'CCI-002418']
  tag nist: ['AC-10', 'SC-23 (3)', 'SC-8']

  describe xml("#{input('webXmlPath')}") do
    its(['/web-app/session-config/cookie-config/http-only']) { should cmp "#{input('cookieHttpOnly')}" }
  end
end
