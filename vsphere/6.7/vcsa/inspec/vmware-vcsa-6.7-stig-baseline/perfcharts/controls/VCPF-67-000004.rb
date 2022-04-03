control 'VCPF-67-000004' do
  title "Performance Charts must protect cookies from cross-site scripting
(XSS)."
  desc  "Cookies are a common way to save session state over the HTTP(S)
protocol. If an attacker can compromise session data stored in a cookie, they
are better able to launch an attack against the server and its applications.
When a cookie is tagged with the \"HttpOnly\" flag, it tells the browser that
this particular cookie should only be accessed by the originating server. Any
attempt to access the cookie from client script is strictly forbidden.


  "
  desc  'rationale', ''
  desc  'check', "
    At the command prompt, execute the following command:

    # xmllint --format
/usr/lib/vmware-perfcharts/tc-instance/webapps/statsreport/WEB-INF/web.xml |
sed '2 s/xmlns=\".*\"//g' | xmllint --xpath
'/web-app/session-config/cookie-config/http-only' -

    Expected result:

    <http-only>true</http-only>

    If the output does not match the expected result, this is a finding.
  "
  desc 'fix', "
    Navigate to and open
/usr/lib/vmware-perfcharts/tc-instance/webapps/statsreport/WEB-INF/web.xml.

    Navigate to the <session-config> node and configure it as follows:

    <session-config>
          <cookie-config>
             <http-only>true</http-only>
             <secure>true</secure>
          </cookie-config>
          <session-timeout>6</session-timeout>
    </session-config>
  "
  impact 0.5
  tag severity: 'medium'
  tag gtitle: 'SRG-APP-000001-WSR-000002'
  tag satisfies: ['SRG-APP-000001-WSR-000002', 'SRG-APP-000439-WSR-000154']
  tag gid: 'V-239405'
  tag rid: 'SV-239405r816582_rule'
  tag stig_id: 'VCPF-67-000004'
  tag fix_id: 'F-42597r816581_fix'
  tag cci: ['CCI-000054', 'CCI-002418']
  tag nist: ['AC-10', 'SC-8']

  describe xml("#{input('statswebXmlPath')}") do
    its(['/web-app/session-config/cookie-config/http-only']) { should cmp "#{input('cookieHttpOnly')}" }
  end
end
