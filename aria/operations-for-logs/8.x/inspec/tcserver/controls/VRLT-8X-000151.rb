control 'VRLT-8X-000151' do
  title 'The VMware Aria Operations for Logs tc Server must set ALLOW_BACKSLASH to false.'
  desc  "When tc Server is installed behind a proxy configured to only allow access to certain contexts (web applications), an HTTP request containing \"/\\../\" may allow attackers to work around the proxy restrictions using directory traversal attack methods. If allow_backslash is true the '\\' character will be permitted as a path delimiter. The default value for the setting is false but tc Server should always be configured as if no proxy restricting context access was used and allow_backslash should be set to false to prevent directory traversal style attacks. This setting can create operability issues with non-compliant clients. "
  desc  'rationale', ''
  desc  'check', "
    At the command prompt, run the following commands:

    # grep -i ALLOW_BACKSLASH /usr/lib/loginsight/application/3rd_party/apache-tomcat/conf/catalina.properties

    If there are no results, this is not a finding.

    If the setting org.apache.catalina.connector.ALLOW_BACKSLASH is present and not set to false, this is a finding.
  "
  desc 'fix', "
    Edit the /usr/lib/loginsight/application/3rd_party/apache-tomcat/conf/catalina.properties file.

    Either remove or edit the org.apache.catalina.connector.ALLOW_BACKSLASH setting. If present, ensure the value is set to false.

    EXAMPLE:
    ...
    org.apache.catalina.connector.ALLOW_BACKSLASH=false
    ...

    Restart the service:
    # systemctl restart loginsight.service
  "
  impact 0.5
  tag severity: 'medium'
  tag gtitle: 'SRG-APP-000516-AS-000237'
  tag gid: 'V-VRLT-8X-000151'
  tag rid: 'SV-VRLT-8X-000151'
  tag stig_id: 'VRLT-8X-000151'
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
