control 'TCSV-00-000151' do
  title 'ALLOW_BACKSLASH must be set to false.'
  desc  "When tc Server is installed behind a proxy configured to only allow access to certain contexts (web applications), an HTTP request containing \"/\\../\" may allow attackers to work around the proxy restrictions using directory traversal attack methods. If allow_backslash is true the '\\' character will be permitted as a path delimiter. The default value for the setting is false but tc Server should always be configured as if no proxy restricting context access was used and allow_backslash should be set to false to prevent directory traversal style attacks. This setting can create operability issues with non-compliant clients. "
  desc  'rationale', ''
  desc  'check', "
    At the command prompt, run the following command:

    # grep -i ALLOW_BACKSLASH $CATALINA_BASE/conf/catalina.properties

    If the setting org.apache.catalina.connector.ALLOW_BACKSLASH is present and set to true, this is a finding.
  "
  desc 'fix', "
    Edit the $CATALINA_BASE/conf/catalina.properties file.

    Add or change the \"org.apache.catalina.connector.ALLOW_BACKSLASH\" setting to \"false\".

    EXAMPLE catalina.properties:
    ...
    org.apache.catalina.startup.EXIT_ON_INIT_FAILURE=true
    org.apache.catalina.connector.ALLOW_BACKSLASH=false
    ...

    Restart the service:
    # systemctl restart loginsight.service
  "
  impact 0.5
  tag severity: 'medium'
  tag gtitle: 'SRG-APP-000516-AS-000237'
  tag gid: 'V-TCSV-00-000151'
  tag rid: 'SV-TCSV-00-000151'
  tag stig_id: 'TCSV-00-000151'
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']

  # Check catalina.properties file
  props = parse_config(file("#{input('catalinaBase')}/conf/catalina.properties").content)

  describe props do
    its(['org.apache.catalina.connector.ALLOW_BACKSLASH']) { should cmp 'false' }
  end
end
