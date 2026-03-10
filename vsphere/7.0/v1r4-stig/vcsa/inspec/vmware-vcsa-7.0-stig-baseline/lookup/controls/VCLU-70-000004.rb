control 'VCLU-70-000004' do
  title 'Lookup Service must protect cookies from cross-site scripting (XSS).'
  desc 'Cookies are a common way to save session state over the HTTP(S) protocol. If an attacker can compromise session data stored in a cookie, they are better able to launch an attack against the server and its applications.

When a cookie is tagged with the "HttpOnly" flag, it tells the browser that this particular cookie should only be accessed by the originating server. Any attempt to access the cookie from client script is strictly forbidden.

'
  desc 'check', %q(At the command prompt, run the following command:

# xmllint --format /usr/lib/vmware-lookupsvc/conf/context.xml | xmllint --xpath '/Context/@useHttpOnly' -

Expected result:

useHttpOnly="true"

If the output does not match the expected result, this is a finding.)
  desc 'fix', 'Navigate to and open:

/usr/lib/vmware-lookupsvc/conf/context.xml

Add the following configuration to the <Context> node:

useHttpOnly="true"

Example:

<Context useHttpOnly="true">

Restart the service with the following command:

# vmon-cli --restart lookupsvc'
  impact 0.5
  tag check_id: 'C-60384r888716_chk'
  tag severity: 'medium'
  tag gid: 'V-256709'
  tag rid: 'SV-256709r888718_rule'
  tag stig_id: 'VCLU-70-000004'
  tag gtitle: 'SRG-APP-000001-WSR-000002'
  tag fix_id: 'F-60327r888717_fix'
  tag satisfies: ['SRG-APP-000001-WSR-000002', 'SRG-APP-000223-WSR-000011', 'SRG-APP-000439-WSR-000154']
  tag cci: ['CCI-000054', 'CCI-001664', 'CCI-002418']
  tag nist: ['AC-10', 'SC-23 (3)', 'SC-8']

  describe xml("#{input('contextXmlPath')}") do
    its(['/Context/@useHttpOnly']) { should cmp "#{input('cookieHttpOnly')}" }
  end
end
