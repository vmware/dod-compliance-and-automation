control 'VRLT-8X-000129' do
  title 'The VMware Aria Operations for Logs tc Server must have the http-only flag set for cookies.'
  desc  "
    It is possible to steal or manipulate web application session and cookies without having a secure cookie. Configuring the secure flag injects the setting into the response header.  When you tag a cookie with the HttpOnly flag, it tells the browser that this particular cookie should only be accessed by the server. Any attempt to access the cookie from client script is forbidden.

    The web.xml file controls how all applications handle cookies via the <cookie-config> element.
  "
  desc  'rationale', ''
  desc  'check', "
    At the command prompt, run the following command:

    # xmllint --xpath \"//*[local-name()='cookie-config']/parent::*\" /usr/lib/loginsight/application/3rd_party/apache-tomcat/conf/web.xml

    If the command returns no results or if the <http-only> element is not set to true, this is a finding.

    EXAMPLE:
    <session-config>
      <session-timeout>15</session-timeout>
      <cookie-config>
        <http-only>true</http-only>
        <secure>true</secure>
      </cookie-config>
    </session-config>
  "
  desc 'fix', "
    Edit the /usr/lib/loginsight/application/3rd_party/apache-tomcat/conf/web.xml file.

    If the cookie-config section does not exist it must be added. Add or modify the <http-only> setting and set to true.

    EXAMPLE:
    <session-config>
      <session-timeout>15</session-timeout>
      <cookie-config>
        <http-only>true</http-only>
        <secure>true</secure>
      </cookie-config>
    </session-config>
  "
  impact 0.5
  tag severity: 'medium'
  tag gtitle: 'SRG-APP-000033-AS-000024'
  tag gid: 'V-VRLT-8X-000129'
  tag rid: 'SV-VRLT-8X-000129'
  tag stig_id: 'VRLT-8X-000129'
  tag cci: ['CCI-000213']
  tag nist: ['AC-3']

  # Open web.xml
  xmlconf = xml("#{input('catalinaBase')}/conf/web.xml")

  # find the cookie-config/http-only, if there, and check its value
  describe xmlconf['//session-config/cookie-config/http-only'] do
    it { should eq ['true'] }
  end
end
