control 'VCEM-80-000070' do
  title 'The vCenter ESX Agent Manager service must set an inactive timeout for sessions.'
  desc 'Leaving sessions open indefinitely is a major security risk. An attacker can easily use an already authenticated session to access the hosted application as the previously authenticated user. By closing sessions after a set period of inactivity, the web server can make certain that those sessions that are not closed through the user logging out of an application are eventually closed.
'
  desc 'check', %q(At the command prompt, run the following command:

# xmllint --format /usr/lib/vmware-eam/web/webapps/eam/WEB-INF/web.xml | sed 's/xmlns=".*"//g' | xmllint --xpath '/web-app/session-config/session-timeout' -

Example result:

<session-timeout>30</session-timeout>

If the value of "session-timeout" is not "30" or less, or is missing, this is a finding.

A value of "0" disables the session timeout. If the value of "session-timeout" is "0", this is a finding.)
  desc 'fix', 'Navigate to and open:

/usr/lib/vmware-eam/web/webapps/eam/WEB-INF/web.xml

Navigate to the <session-config> node and configure the <session-timeout> as follows:

<session-config>
  <session-timeout>30</session-timeout>
  <cookie-config>
      <http-only>true</http-only>
      <secure>true</secure>
  </cookie-config>
</session-config>

Restart the service with the following command:

# vmon-cli --restart eam'
  impact 0.5
  tag check_id: 'C-62755r934701_chk'
  tag severity: 'medium'
  tag gid: 'V-259015'
  tag rid: 'SV-259015r1003617_rule'
  tag stig_id: 'VCEM-80-000070'
  tag gtitle: 'SRG-APP-000295-AS-000263'
  tag fix_id: 'F-62664r934702_fix'
  tag satisfies: ['SRG-APP-000295-AS-000263', 'SRG-APP-000389-AS-000253']
  tag cci: ['CCI-004895', 'CCI-002361']
  tag nist: ['SC-11 b', 'AC-12']

  # Open web.xml
  xmlconf = xml(input('webXmlPath'))

  # find the session-timeout value
  describe xmlconf['//session-config/session-timeout'] do
    it { should cmp ["#{input('sessionTimeout')}"] }
    it { should_not cmp 0 }
  end
end
