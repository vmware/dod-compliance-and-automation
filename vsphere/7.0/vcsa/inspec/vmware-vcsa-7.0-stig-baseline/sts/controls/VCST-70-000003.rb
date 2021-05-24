# encoding: UTF-8

control 'VCST-70-000003' do
  title "The Security Token Service must limit the maximum size of a POST
request."
  desc  "Cookies are a common way to save session state over the HTTP(S)
protocol. If an attacker can compromise session data stored in a cookie, they
are better able to launch an attack against the server and its applications.

    When a cookie is tagged with the \"HttpOnly\" flag, it tells the browser
that this particular cookie should only be accessed by the originating server.
Any attempt to access the cookie from client script is strictly forbidden.
  "
  desc  'rationale', ''
  desc  'check', "
    At the command prompt, execute the following command:

    # xmllint --xpath
'/Server/Service/Connector[@port=\"${bio-custom.http.port}\"]/@maxPostSize'
/usr/lib/vmware-sso/vmware-sts/conf/server.xml

    Expected result:

    XPath set is empty

    If the output does not match the expected result, this is a finding.
  "
  desc  'fix', "
    Navigate to and open:

    /usr/lib/vmware-sso/vmware-sts/conf/server.xml

    Navigate to each of the <Connector> nodes.

    Remove any configuration for \"maxPostSize\".
  "
  impact 0.5
  tag severity: 'medium'
  tag gtitle: 'SRG-APP-000001-WSR-000001'
  tag gid: nil
  tag rid: nil
  tag stig_id: 'VCST-70-000003'
  tag fix_id: nil
  tag cci: 'CCI-000054'
  tag nist: ['AC-10']

  describe xml("#{input('serverXmlPath')}") do
    its('Server/Service/Connector/attribute::maxPostSize') { should eq [] }
  end

end

