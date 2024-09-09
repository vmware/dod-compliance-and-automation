control 'VRPU-8X-000005' do
  title 'The VMware Aria Operations UI service cookies must have the secure flag set.'
  desc  "
    It is possible to steal or manipulate web application session and cookies without having a secure cookie. Configuring the secure flag injects the setting into the response header.

    The $CATALINA_BASE/conf/web.xml file controls how each application handles cookies via the <cookie-config> element.
  "
  desc  'rationale', ''
  desc  'check', "
    At the command prompt, run the following command:

    xmllint --xpath \"//*[local-name()='cookie-config']/parent::*\" /usr/lib/vmware-vcops/tomcat-web-app/conf/web.xml

    If the command returns no results or if the <cookie-config><secure> element is not set to true, this is a finding.

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
    Edit the /usr/lib/vmware-vcops/tomcat-web-app/conf/web.xml.

    If the cookie-config section does not exist it must be added. Add or modify the <secure> setting as a child node to the <cookie-config> node and set its value to true.

    EXAMPLE:
    <web-app>
    ...
      <session-config>
        <session-timeout>15</session-timeout>
        <cookie-config>
          <http-only>true</http-only>
          <secure>true</secure>
        </cookie-config>
      </session-config>
    ...
    </web-app>

    Restart the service:
    # systemctl restart vmware-vcops-web.service
  "
  impact 0.5
  tag severity: 'medium'
  tag gtitle: 'SRG-APP-000033-AS-000024'
  tag gid: 'V-VRPU-8X-000005'
  tag rid: 'SV-VRPU-8X-000005'
  tag stig_id: 'VRPU-8X-000005'
  tag cci: ['CCI-000213']
  tag nist: ['AC-3']

  # Open web.xml
  xmlconf = xml(input('ui-webXmlPath'))

  # find the cookie-config/secure value
  describe xmlconf['//session-config/cookie-config/secure'] do
    it { should eq ['true'] }
  end
end
