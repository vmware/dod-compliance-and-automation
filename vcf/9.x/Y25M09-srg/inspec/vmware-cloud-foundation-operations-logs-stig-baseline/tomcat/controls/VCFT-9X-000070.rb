control 'VCFT-9X-000070' do
  title 'The VMware Cloud Foundation Operations for Logs Loginsight service must set an inactive timeout for sessions.'
  desc  'Leaving sessions open indefinitely is a major security risk. An attacker can easily use an already authenticated session to access the hosted application as the previously authenticated user. By closing sessions after a set period of inactivity, the web server can make certain that those sessions that are not closed through the user logging out of an application are eventually closed. '
  desc  'rationale', ''
  desc  'check', "
    At the command prompt, run the following:

    # xmllint --xpath \"//*[local-name()='session-timeout']/parent::*\" /usr/lib/loginsight/application/3rd_party/apache-tomcat/conf/web.xml

    Example result:

    <session-config>
    \t<session-timeout>30</session-timeout>
    \t<cookie-config>
    \t\t<http-only>true</http-only>
    \t\t<secure>true</secure>
    \t</cookie-config>
    </session-config>

    If the value of \"session-timeout\" is not \"30\" or less, or is missing, this is a finding.
  "
  desc 'fix', "
    Navigate to and open:

    /usr/lib/loginsight/application/3rd_party/apache-tomcat/conf/web.xml

    Navigate to the <session-config> node and add or update the <session-timeout> as follows:

    <session-config>
    \t<session-timeout>30</session-timeout>
    \t<cookie-config>
    \t\t<http-only>true</http-only>
    \t\t<secure>true</secure>
    \t</cookie-config>
    </session-config>

    Restart the service with the following command:

    # systemctl restart loginsight.service
  "
  impact 0.5
  tag severity: 'medium'
  tag gtitle: 'SRG-APP-000295-AS-000263'
  tag satisfies: ['SRG-APP-000389-AS-000253']
  tag gid: 'V-VCFT-9X-000070'
  tag rid: 'SV-VCFT-9X-000070'
  tag stig_id: 'VCFT-9X-000070'
  tag cci: ['CCI-002038', 'CCI-002361']
  tag nist: ['AC-12', 'IA-11']

  # Open web.xml
  xmlconf = xml("#{input('catalinaBase')}/conf/web.xml")

  # find the session-timeout value
  describe xmlconf['//session-config/session-timeout'] do
    it { should eq ["#{input('sessionTimeout')}"] }
  end
end
