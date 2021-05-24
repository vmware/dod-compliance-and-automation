# encoding: UTF-8

control 'VCST-70-000004' do
  title 'The Security Token Service must protect cookies from XSS.'
  desc  "Remote access can be exploited by an attacker to compromise the
server. By recording all remote access activities, it will be possible to
determine the attacker's location, intent, and degree of success.

    Tomcat can be configured with an \"AccessLogValve\", a component that can
be inserted into the request processing pipeline to provide robust access
logging. The AccessLogValve creates log files in the same format as those
created by standard web servers. When AccessLogValve is properly configured,
log files will contain all the forensic information necessary in the case of a
security incident.
  "
  desc  'rationale', ''
  desc  'check', "
    At the command prompt, execute the following command:

    # xmllint --format /usr/lib/vmware-sso/vmware-sts/conf/web.xml | sed '2
s/xmlns=\".*\"//g' | xmllint --xpath
'/web-app/session-config/cookie-config/http-only' -

    Expected result:

    <http-only>true</http-only>

    If the output does not match the expected result, this is a finding.
  "
  desc  'fix', "
    Navigate to and open:

    /usr/lib/vmware-sso/vmware-sts/conf/web.xml

    Navigate to the <session-config> node and configure it as follows:

    <session-config>
            <session-timeout>30</session-timeout>
            <cookie-config>
                <http-only>true</http-only>
                <secure>true</secure>
           </cookie-config>
    </session-config>
  "
  impact 0.5
  tag severity: 'medium'
  tag gtitle: 'SRG-APP-000001-WSR-000002'
  tag gid: nil
  tag rid: nil
  tag stig_id: 'VCST-70-000004'
  tag fix_id: nil
  tag cci: 'CCI-000054'
  tag nist: ['AC-10']

  describe xml("#{input('webXmlPath')}") do
    its(['/web-app/session-config/cookie-config/http-only']) { should cmp "#{input('cookieHttpOnly')}" }
  end

end

