control 'VCLU-80-000151' do
  title 'The vCenter Lookup service must disable "ALLOW_BACKSLASH".'
  desc 'When Tomcat is installed behind a proxy configured to only allow access to certain contexts (web applications), an HTTP request containing "/\\../" may allow attackers to work around the proxy restrictions using directory traversal attack methods. If "allow_backslash" is "true", the "\\" character will be permitted as a path delimiter. The default value for the setting is "false", but Tomcat must always be configured as if no proxy restricting context access was used, and "allow_backslash" should be set to "false" to prevent directory-traversal-style attacks. This setting can create operability issues with noncompliant clients.'
  desc 'check', 'At the command line, run the following command:

# grep ALLOW_BACKSLASH /usr/lib/vmware-lookupsvc/conf/catalina.properties

Example result:

org.apache.catalina.connector.ALLOW_BACKSLASH=false

If "org.apache.catalina.connector.ALLOW_BACKSLASH" is not set to "false", this is a finding.

If the "org.apache.catalina.connector.ALLOW_BACKSLASH" setting does not exist, this is not a finding.'
  desc 'fix', 'Navigate to and open:

/usr/lib/vmware-lookupsvc/conf/catalina.properties

Update or remove the following line:

org.apache.catalina.connector.ALLOW_BACKSLASH=false

Restart the service with the following command:

# vmon-cli --restart lookupsvc'
  impact 0.5
  tag check_id: 'C-62807r934857_chk'
  tag severity: 'medium'
  tag gid: 'V-259067'
  tag rid: 'SV-259067r934859_rule'
  tag stig_id: 'VCLU-80-000151'
  tag gtitle: 'SRG-APP-000516-AS-000237'
  tag fix_id: 'F-62716r934858_fix'
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']

  describe parse_config_file("#{input('catalinaPropertiesPath')}").params['org.apache.catalina.connector.ALLOW_BACKSLASH'] do
    it { should be_in [nil, 'false'] }
  end
end
