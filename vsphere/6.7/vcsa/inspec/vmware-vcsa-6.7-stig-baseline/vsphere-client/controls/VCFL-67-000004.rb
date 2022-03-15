control 'VCFL-67-000004' do
  title 'vSphere Client must protect cookies from XSS.'
  desc "Cookies are a common way to save session state over the HTTP(S)
protocol. If an attacker can compromise session data stored in a cookie, they
are better able to launch an attack against the server and its applications.

    When a cookie is tagged with the \"HttpOnly\" flag, it tells the browser
that this particular cookie should only be accessed by the originating server.
Any attempt to access the cookie from client script is strictly forbidden.
  "
  desc  'rationale', ''
  desc  'check', "
    At the command prompt, execute the following command:

    # xmllint --xpath '/Context/@useHttpOnly'
/usr/lib/vmware-vsphere-client/server/configuration/context.xml

    Expected result:

    useHttpOnly=\"true\"

    If the output does not match the expected result, this is a finding.
  "
  desc 'fix', "
    Navigate to and open
/usr/lib/vmware-vsphere-client/server/configuration/context.xml.

    Configure the <Context> node as follows:

    <Context useHttpOnly=\"true\">
  "
  impact 0.5
  tag severity: 'medium'
  tag gtitle: 'SRG-APP-000001-WSR-000002'
  tag satisfies: %w(SRG-APP-000001-WSR-000002 SRG-APP-000223-WSR-000011
 SRG-APP-000439-WSR-000154)
  tag gid: 'V-239746'
  tag rid: 'SV-239746r679465_rule'
  tag stig_id: 'VCFL-67-000004'
  tag fix_id: 'F-42938r679464_fix'
  tag cci: %w(CCI-000054 CCI-001664 CCI-002418)
  tag nist: ['AC-10', 'SC-23 (3)', 'SC-8']

  describe xml('/usr/lib/vmware-vsphere-client/server/configuration/context.xml') do
    its(['Context/attribute::useHttpOnly']) { should eq ['true'] }
  end
end
