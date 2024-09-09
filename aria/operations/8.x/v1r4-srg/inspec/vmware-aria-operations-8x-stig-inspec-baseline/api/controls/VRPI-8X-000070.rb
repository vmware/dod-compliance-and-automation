control 'VRPI-8X-000070' do
  title 'The VMware Aria Operations API service must set an inactive timeout for sessions.'
  desc  'Leaving sessions open indefinitely is a major security risk. An attacker can easily use an already authenticated session to access the hosted application as the previously authenticated user. By closing sessions after a set period of inactivity, the web server can make certain that those sessions that are not closed through the user logging out of an application are eventually closed.'
  desc  'rationale', ''
  desc  'check', "
    At the command prompt, run the following command:

    # xmllint --xpath \"//*[local-name()='session-timeout']/parent::*\" /usr/lib/vmware-vcops/tomcat-enterprise/conf/web.xml

    If the value of <session-timeout> is not \"30\" or less, or is missing, this is a finding.

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
    Edit the /usr/lib/vmware-vcops/tomcat-enterprise/conf/web.xml file.

    Navigate to the <session-config> node.

    Add or edit the <session-timeout>30</session-timeout> node setting in the <session-config> node.

    EXAMPLE:
    <session-config>
      <session-timeout>30</session-timeout>
      <cookie-config>
        <http-only>true</http-only>
        <secure>true</secure>
      </cookie-config>
    </session-config>

    Restart the service:
    # systemctl restart api.service
  "
  impact 0.5
  tag severity: 'medium'
  tag gtitle: 'SRG-APP-000295-AS-000263'
  tag satisfies: ['SRG-APP-000389-AS-000253']
  tag gid: 'V-VRPI-8X-000070'
  tag rid: 'SV-VRPI-8X-000070'
  tag stig_id: 'VRPI-8X-000070'
  tag cci: ['CCI-002038', 'CCI-002361']
  tag nist: ['AC-12', 'IA-11']

  # Open web.xml
  xmlconf = xml(input('api-webXmlPath'))

  # find the session-timeout value
  describe xmlconf['//session-config/session-timeout'] do
    it { should eq ["#{input('api-sessionTimeout')}"] }
  end
end
