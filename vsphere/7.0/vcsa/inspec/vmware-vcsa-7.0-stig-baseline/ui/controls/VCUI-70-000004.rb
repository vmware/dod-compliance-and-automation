control 'VCUI-70-000004' do
  title 'vSphere UI must protect cookies from cross-site scripting (XSS).'
  desc 'Cookies are a common way to save session state over the HTTP(S) protocol. If an attacker can compromise session data stored in a cookie, they are better able to launch an attack against the server and its applications. When a cookie is tagged with the "HttpOnly" flag, it tells the browser this particular cookie should only be accessed by the originating server. Any attempt to access the cookie from client script is strictly forbidden.

'
  desc 'check', %q(At the command prompt, run the following command:

# xmllint --format /usr/lib/vmware-vsphere-ui/server/conf/context.xml | xmllint --xpath '/Context/@useHttpOnly' -

Expected result:

useHttpOnly="true"

If the output does not match the expected result, this is a finding.)
  desc 'fix', 'Navigate to and open:

/usr/lib/vmware-vsphere-ui/server/conf/context.xml

Add the following configuration to the <Context> node:

useHttpOnly="true"

Example:

<Context useHttpOnly="true" sessionCookieName="VSPHERE-UI-JSESSIONID" sessionCookiePath="/ui">

Restart the service with the following command:

# vmon-cli --restart vsphere-ui'
  impact 0.5
  tag check_id: 'C-60456r889340_chk'
  tag severity: 'medium'
  tag gid: 'V-256781'
  tag rid: 'SV-256781r889342_rule'
  tag stig_id: 'VCUI-70-000004'
  tag gtitle: 'SRG-APP-000001-WSR-000002'
  tag fix_id: 'F-60399r889341_fix'
  tag satisfies: ['SRG-APP-000001-WSR-000002', 'SRG-APP-000439-WSR-000154']
  tag cci: ['CCI-000054', 'CCI-002418']
  tag nist: ['AC-10', 'SC-8']

  describe xml("#{input('contextXmlPath')}") do
    its(['/Context/@useHttpOnly']) { should cmp "#{input('cookieHttpOnly')}" }
  end
end
