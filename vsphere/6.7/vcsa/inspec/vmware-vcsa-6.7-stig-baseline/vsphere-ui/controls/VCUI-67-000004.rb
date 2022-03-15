control 'VCUI-67-000004' do
  title 'vSphere UI must protect cookies from XSS.'
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

    # xmllint --format /usr/lib/vmware-vsphere-ui/server/conf/context.xml |
xmllint --xpath '/Context/@useHttpOnly' -

    Expected result:

    useHttpOnly=\"true\"

    If the output does not match the expected result, this is a finding.
  "
  desc 'fix', "
    Navigate to and open /usr/lib/vmware-vsphere-ui/server/conf/context.xml.

    Add the following configuration to the <Context> node:

    useHttpOnly=\"true\"

    Example:

    <Context useHttpOnly=\"true\" sessionCookieName=\"VSPHERE-UI-JSESSIONID\"
sessionCookiePath=\"/ui\">
  "
  impact 0.5
  tag severity: 'medium'
  tag gtitle: 'SRG-APP-000001-WSR-000002'
  tag satisfies: %w(SRG-APP-000001-WSR-000002 SRG-APP-000439-WSR-000154)
  tag gid: 'V-239685'
  tag rid: 'SV-239685r679161_rule'
  tag stig_id: 'VCUI-67-000004'
  tag fix_id: 'F-42877r679160_fix'
  tag cci: %w(CCI-000054 CCI-002418)
  tag nist: %w(AC-10 SC-8)

  describe xml("#{input('contextXmlPath')}") do
    its(['/Context/@useHttpOnly']) { should cmp "#{input('cookieHttpOnly')}" }
  end
end
