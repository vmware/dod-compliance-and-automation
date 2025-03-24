control 'VCST-80-000129' do
  title 'The vCenter STS service cookies must have "http-only" flag set.'
  desc 'Cookies are a common way to save session state over the HTTP(S) protocol. If attackers can compromise session data stored in a cookie, they are better able to launch an attack against the server and its applications. When a cookie is tagged with the "HttpOnly" flag, it tells the browser this particular cookie should only be accessed by the originating server. Any attempt to access the cookie from client script is strictly forbidden.'
  desc 'check', %q(At the command prompt, run the following command:

# xmllint --format /usr/lib/vmware-sso/vmware-sts/conf/web.xml | sed 's/xmlns=".*"//g' | xmllint --xpath '/web-app/session-config/cookie-config/http-only' -

Expected result:

<http-only>true</http-only>

If the output does not match the expected result, this is a finding.)
  desc 'fix', 'Navigate to and open:

/usr/lib/vmware-sso/vmware-sts/conf/web.xml

Navigate to the <session-config> node and configure the <http-only> as follows:

<session-config>
  <session-timeout>30</session-timeout>
  <cookie-config>
      <http-only>true</http-only>
      <secure>true</secure>
  </cookie-config>
</session-config>

Restart the service with the following command:

# vmon-cli --restart sts'
  impact 0.5
  tag check_id: 'C-62728r934620_chk'
  tag severity: 'medium'
  tag gid: 'V-258988'
  tag rid: 'SV-258988r960792_rule'
  tag stig_id: 'VCST-80-000129'
  tag gtitle: 'SRG-APP-000033-AS-000024'
  tag fix_id: 'F-62637r934621_fix'
  tag cci: ['CCI-000213']
  tag nist: ['AC-3']

  # Open web.xml
  xmlconf = xml(input('webXmlPath'))

  # find the cookie-config/http-only, if there, and check its value
  describe xmlconf['//session-config/cookie-config/http-only'] do
    it { should eq ['true'] }
  end
end
