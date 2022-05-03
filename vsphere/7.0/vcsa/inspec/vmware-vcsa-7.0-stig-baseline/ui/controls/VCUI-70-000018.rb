control 'VCUI-70-000018' do
  title "vSphere UI must restrict it's cookie path."
  desc  "
    Cookies are used to exchange data between the web server and the client. Cookies, such as a session cookie, may contain session information and user credentials used to maintain a persistent connection between the user and the hosted application since HTTP/HTTPS is a stateless protocol.

    vSphere UI is bound to the \"/ui\" virtual path behind the reverse proxy and it's cookies are configured as such. This configuration must be confirmed and maintained.
  "
  desc  'rationale', ''
  desc  'check', "
    At the command prompt, execute the following command:

    # xmllint --format /usr/lib/vmware-vsphere-ui/server/conf/context.xml | xmllint --xpath '/Context/@sessionCookiePath' -

    Expected result:

    sessionCookiePath=\"/ui\"

    If the output does not match the expected result, this is a finding.
  "
  desc 'fix', "
    Navigate to and open:

    /usr/lib/vmware-vsphere-ui/server/conf/context.xml

    Add the following configuration to the <Context> node:

    sessionCookiePath=\"/ui\"

    Example:

    <Context useHttpOnly=\"true\" sessionCookieName=\"VSPHERE-UI-JSESSIONID\" sessionCookiePath=\"/ui\">

    Restart the service with the following command:

    # vmon-cli --restart vsphere-ui
  "
  impact 0.5
  tag severity: 'medium'
  tag gtitle: 'SRG-APP-000223-WSR-000011'
  tag gid: nil
  tag rid: nil
  tag stig_id: 'VCUI-70-000018'
  tag cci: ['CCI-001664']
  tag nist: ['SC-23 (3)']

  describe xml("#{input('contextXmlPath')}") do
    its(['/Context/@sessionCookiePath']) { should cmp "#{input('sessionCookiePath')}" }
  end
end
