control 'VCST-70-000028' do
  title 'The Security Token Service must be configured with the appropriate ports.'
  desc 'Web servers provide numerous processes, features, and functionalities that use TCP/IP ports. Some of these processes may be deemed unnecessary or too unsecure to run on a production system. The ports that the Security Token Service listens on are configured in the "catalina.properties" file and must be verified as accurate to their shipping state.'
  desc 'check', "At the command prompt, run the following command:

# grep 'bio' /usr/lib/vmware-sso/vmware-sts/conf/catalina.properties

Expected result:

bio-custom.http.port=7080
bio-custom.https.port=8443
bio-ssl-clientauth.https.port=3128
bio-ssl-localhost.https.port=7444

If the output of the command does not match the expected result, this is a finding.

Note: Port 3128 will not be shown in the output prior to 7.0 U3i."
  desc 'fix', 'Navigate to and open:

/usr/lib/vmware-sso/vmware-sts/conf/catalina.properties

Navigate to the ports specification section.

Set the Security Token Service port specifications according to the following list:

bio-custom.http.port=7080
bio-custom.https.port=8443
bio-ssl-clientauth.https.port=3128
bio-ssl-localhost.https.port=7444

Restart the service with the following command:

# vmon-cli --restart sts'
  impact 0.5
  tag check_id: 'C-60446r918977_chk'
  tag severity: 'medium'
  tag gid: 'V-256771'
  tag rid: 'SV-256771r918979_rule'
  tag stig_id: 'VCST-70-000028'
  tag gtitle: 'SRG-APP-000383-WSR-000175'
  tag fix_id: 'F-60389r918978_fix'
  tag cci: ['CCI-001762']
  tag nist: ['CM-7 (1) (b)']

  describe parse_config_file("#{input('catalinaPropertiesPath')}").params['bio-custom.http.port'] do
    it { should eq "#{input('httpPort')}" }
  end
  describe parse_config_file("#{input('catalinaPropertiesPath')}").params['bio-custom.https.port'] do
    it { should eq "#{input('httpsPort')}" }
  end
  describe parse_config_file("#{input('catalinaPropertiesPath')}").params['bio-ssl-clientauth.https.port'] do
    it { should eq "#{input('clientAuthPort')}" }
  end
  describe parse_config_file("#{input('catalinaPropertiesPath')}").params['bio-ssl-localhost.https.port'] do
    it { should eq "#{input('sslhttpsPort')}" }
  end
end
