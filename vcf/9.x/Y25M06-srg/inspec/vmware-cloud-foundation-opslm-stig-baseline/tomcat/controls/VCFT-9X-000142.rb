control 'VCFT-9X-000142' do
  title 'The VMware Cloud Foundation Operations for Logs Loginsight service must disable "ALLOW_BACKSLASH".'
  desc  'When Apache Tomcat is installed behind a proxy configured to only allow access to certain contexts (web applications), an HTTP request containing "/\\../" may allow attackers to work around the proxy restrictions using directory traversal attack methods. If "allow_backslash" is "true", the "\" character will be permitted as a path delimiter. The default value for the setting is "false", but Tomcat must always be configured as if no proxy restricting context access was used, and "allow_backslash" should be set to "false" to prevent directory traversal attack methods. This setting can create operability issues with noncompliant clients.'
  desc  'rationale', ''
  desc  'check', "
    At the command prompt, run the following:

    # grep ALLOW_BACKSLASH /usr/lib/loginsight/application/3rd_party/apache-tomcat/conf/catalina.properties

    Example result:

    org.apache.catalina.connector.ALLOW_BACKSLASH=false

    If \"org.apache.catalina.connector.ALLOW_BACKSLASH\" is not set to \"false\", this is a finding.

    If the \"org.apache.catalina.connector.ALLOW_BACKSLASH\" setting does not exist, this is not a finding.
  "
  desc 'fix', "
    Navigate to and open:

    /usr/lib/loginsight/application/3rd_party/apache-tomcat/conf/catalina.properties

    Update or remove the following line:

    org.apache.catalina.connector.ALLOW_BACKSLASH=false

    Restart the service with the following command:

    # systemctl restart loginsight.service
  "
  impact 0.5
  tag severity: 'medium'
  tag gtitle: 'SRG-APP-000516-AS-000237'
  tag gid: 'V-VCFT-9X-000142'
  tag rid: 'SV-VCFT-9X-000142'
  tag stig_id: 'VCFT-9X-000142'
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']

  # Check catalina.properties file
  props = parse_config(file("#{input('catalinaBase')}/conf/catalina.properties").content).params['org.apache.catalina.connector.ALLOW_BACKSLASH']

  describe.one do
    describe props do
      it { should cmp false }
    end
    describe props do
      it { should cmp nil }
    end
  end
end
