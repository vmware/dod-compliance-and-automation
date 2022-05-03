control 'VCLU-70-000004' do
  title 'Lookup Service must protect cookies from cross-site scripting (XSS).'
  desc  "
    Cookies are a common way to save session state over the HTTP(S) protocol. If an attacker can compromise session data stored in a cookie, they are better able to launch an attack against the server and its applications.

    When you tag a cookie with the \"HttpOnly\" flag, it tells the browser that this particular cookie should only be accessed by the originating server. Any attempt to access the cookie from client script is strictly forbidden.
  "
  desc  'rationale', ''
  desc  'check', "
    At the command prompt, execute the following command:

    # xmllint --format /usr/lib/vmware-lookupsvc/conf/context.xml | xmllint --xpath '/Context/@useHttpOnly' -

    Expected result:

    useHttpOnly=\"true\"

    If the output does not match the expected result, this is a finding.
  "
  desc 'fix', "
    Navigate to and open:

    /usr/lib/vmware-lookupsvc/conf/context.xml

    Add the following configuration to the <Context> node:

    useHttpOnly=\"true\"

    Example:

    <Context useHttpOnly=\"true\">

    Restart the service with the following command:

    # vmon-cli --restart lookupsvc
  "
  impact 0.5
  tag severity: 'medium'
  tag gtitle: 'SRG-APP-000001-WSR-000002'
  tag satisfies: ['SRG-APP-000223-WSR-000011', 'SRG-APP-000439-WSR-000154']
  tag gid: nil
  tag rid: nil
  tag stig_id: 'VCLU-70-000004'
  tag cci: ['CCI-000054', 'CCI-001664', 'CCI-002418']
  tag nist: ['AC-10', 'SC-23 (3)', 'SC-8']

  describe xml("#{input('contextXmlPath')}") do
    its(['/Context/@useHttpOnly']) { should cmp "#{input('cookieHttpOnly')}" }
  end
end
