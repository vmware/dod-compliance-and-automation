control 'VCST-67-000028' do
  title "The Security Token Service must be configured with the appropriate
ports."
  desc  "Web servers provide numerous processes, features, and functionalities
that use TCP/IP ports. Some of these processes may be deemed unnecessary or too
unsecure to run on a production system. The ports that the Security Token
Service listens on are configured in the \"catalina.properties\" file and must
be verified as accurate to their shipping state."
  desc  'rationale', ''
  desc  'check', "
    Connect to the PSC, whether external or embedded.

    At the command prompt, execute the following command:

    # grep 'bio' /usr/lib/vmware-sso/vmware-sts/conf/catalina.properties

    Expected result:

    bio-custom.http.port=7080
    bio-custom.https.port=8443
    bio-ssl-localhost.https.port=7444

    If the output of the command does not match the expected result, this is a
finding.
  "
  desc 'fix', "
    Connect to the PSC, whether external or embedded.

    Navigate to and open
/usr/lib/vmware-sso/vmware-sts/conf/catalina.properties.

    Navigate to the ports specification section.

    Set the Security Token Service port specifications according to the
following list:

    bio-custom.http.port=7080
    bio-custom.https.port=8443
    bio-ssl-localhost.https.port=7444
  "
  impact 0.5
  tag severity: 'medium'
  tag gtitle: 'SRG-APP-000383-WSR-000175'
  tag gid: 'V-239679'
  tag rid: 'SV-239679r816762_rule'
  tag stig_id: 'VCST-67-000028'
  tag fix_id: 'F-42871r816761_fix'
  tag cci: ['CCI-001762']
  tag nist: ['CM-7 (1) (b)']

  describe parse_config_file("#{input('catalinaPropertiesPath')}").params['bio-custom.http.port'] do
    it { should eq "#{input('httpPort')}" }
  end
  describe parse_config_file("#{input('catalinaPropertiesPath')}").params['bio-custom.https.port'] do
    it { should eq "#{input('httpsPort')}" }
  end
  describe parse_config_file("#{input('catalinaPropertiesPath')}").params['bio-ssl-localhost.https.port'] do
    it { should eq "#{input('sslhttpsPort')}" }
  end
end
