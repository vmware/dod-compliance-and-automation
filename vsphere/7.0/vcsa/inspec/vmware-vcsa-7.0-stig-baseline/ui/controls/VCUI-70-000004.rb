# encoding: UTF-8

control 'VCUI-70-000004' do
  title 'vSphere UI must protect cookies from XSS.'
  desc  "Cookies are a common way to save session state over the HTTP(S)
protocol. If an attacker can compromise session data stored in a cookie, they
are better able to launch an attack against the server and its applications.
When you tag a cookie with the HttpOnly flag, it tells the browser that this
particular cookie should only be accessed by the originating server. Any
attempt to access the cookie from client script is strictly forbidden."
  desc  'rationale', ''
  desc  'check', "
    At the command prompt, execute the following command:

    # xmllint --format /usr/lib/vmware-vsphere-ui/server/conf/context.xml |
xmllint --xpath '/Context/@useHttpOnly' -

    Expected result:

    useHttpOnly=\"true\"

    If the output does not match the expected result, this is a finding.
  "
  desc  'fix', "
    Navigate to and open /usr/lib/vmware-vsphere-ui/server/conf/context.xml .
Add the following configuration to the <Context> node:

    useHttpOnly=\"true\"

    Ex:

    <Context useHttpOnly=\"true\" sessionCookieName=\"VSPHERE-UI-JSESSIONID\"
sessionCookiePath=\"/ui\">
  "
  impact 0.5
  tag severity: 'medium'
  tag gtitle: 'SRG-APP-000001-WSR-000002'
  tag gid: nil
  tag rid: nil
  tag stig_id: 'VCUI-70-000004'
  tag fix_id: nil
  tag cci: 'CCI-000054'
  tag nist: ['AC-10']

  describe xml("#{input('contextXmlPath')}") do
    its(['/Context/@useHttpOnly']) { should cmp "#{input('cookieHttpOnly')}" }
  end

end

