control 'VCFT-9X-000005' do
  title 'The VMware Cloud Foundation Operations for Logs Loginsight service must have the secure flag set for cookies.'
  desc  "
    The secure flag is an option that can be set by the application server when sending a new cookie to the user within an HTTP Response. The purpose of the secure flag is to prevent cookies from being observed by unauthorized parties due to the transmission of a cookie in clear text.

    By setting the secure flag, the browser will prevent the transmission of a cookie over an unencrypted channel.
  "
  desc  'rationale', ''
  desc  'check', "
    At the command prompt, run the following:

    # xmllint --xpath \"//*[local-name()='cookie-config']/parent::*\" /usr/lib/loginsight/application/3rd_party/apache-tomcat/conf/web.xml

    Example result:

    <session-config>
      <session-timeout>30</session-timeout>
      <cookie-config>
          <http-only>true</http-only>
          <secure>true</secure>
      </cookie-config>
    </session-config>

    If the \"secure\" parameter under \"cookie-config\" is not set to \"true\", this is a finding.
  "
  desc 'fix', "
    Navigate to and open:

    /usr/lib/loginsight/application/3rd_party/apache-tomcat/conf/web.xml

    Navigate to the <session-config> node and configure the <secure> setting as follows:

    <session-config>
      <session-timeout>30</session-timeout>
      <cookie-config>
          <http-only>true</http-only>
          <secure>true</secure>
      </cookie-config>
    </session-config>

    Restart the service with the following command:

    # systemctl restart loginsight.service
  "
  impact 0.5
  tag severity: 'medium'
  tag gtitle: 'SRG-APP-000033-AS-000024'
  tag gid: 'V-VCFT-9X-000005'
  tag rid: 'SV-VCFT-9X-000005'
  tag stig_id: 'VCFT-9X-000005'
  tag cci: ['CCI-000213']
  tag nist: ['AC-3']

  # Open web.xml
  xmlconf = xml("#{input('catalinaBase')}/conf/web.xml")

  # find the cookie-config/secure value
  describe xmlconf['//session-config/cookie-config/secure'] do
    it { should eq ['true'] }
  end
end
