control 'VRPS-8X-000129' do
  title 'The VMware Aria Operations Casa service cookies must have the "http-only" flag set.'
  desc  'It is possible to steal or manipulate web application session and cookies without having a secure cookie. Configuring the secure flag injects the setting into the response header.  When you tag a cookie with the HttpOnly flag, it tells the browser that this particular cookie should only be accessed by the server. Any attempt to access the cookie from client script is forbidden.'
  desc  'rationale', ''
  desc  'check', "
    At the command prompt, run the following command:

    # xmllint --xpath \"//*[local-name()='cookie-config']/parent::*\" /usr/lib/vmware-casa/casa-webapp/conf/web.xml

    Example result:

    <session-config>
      <session-timeout>30</session-timeout>
      <cookie-config>
        <http-only>true</http-only>
        <secure>true</secure>
      </cookie-config>
    </session-config>

    If the command returns no results or if the \"<http-only>\" element is not set to true, this is a finding.
  "
  desc 'fix', "
    Edit the /usr/lib/vmware-casa/casa-webapp/conf/web.xml file.

    Navigate to the <session-config> node and configure the <http-only> as follows:

    <session-config>
      <session-timeout>30</session-timeout>
      <cookie-config>
        <http-only>true</http-only>
        <secure>true</secure>
      </cookie-config>
    </session-config>

    Restart the service with the following command:

    # systemctl restart vmware-casa.service
  "
  impact 0.5
  tag severity: 'medium'
  tag gtitle: 'SRG-APP-000033-AS-000024'
  tag gid: 'V-VRPS-8X-000129'
  tag rid: 'SV-VRPS-8X-000129'
  tag stig_id: 'VRPS-8X-000129'
  tag cci: ['CCI-000213']
  tag nist: ['AC-3']

  # Open web.xml
  xmlconf = xml(input('casa-webXmlPath'))

  # find the cookie-config/http-only, if there, and check its value
  describe xmlconf['//session-config/cookie-config/http-only'] do
    it { should eq ['true'] }
  end
end
