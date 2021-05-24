# encoding: UTF-8

control 'VCST-70-000028' do
  title "The Security Token Service must be configured with the appropriate
ports."
  desc  "An attacker has at least two reasons to stop a web server. The first
is to cause a denial of service, and the second is to put in place changes the
attacker made to the web server configuration.

    If the Tomcat shutdown port feature is enabled, a shutdown signal can be
sent to the Security Token Service through this port. To ensure availability,
the shutdown port must be disabled.
  "
  desc  'rationale', ''
  desc  'check', "
    At the command prompt, execute the following command:

    # grep 'bio' /usr/lib/vmware-sso/vmware-sts/conf/catalina.properties

    Expected result:

    bio-custom.http.port=7080
    bio-custom.https.port=8443
    bio-ssl-localhost.https.port=7444

    If the output of the command does not match the expected result, this is a
finding.
  "
  desc  'fix', "
    Navigate to and open:

    /usr/lib/vmware-sso/vmware-sts/conf/catalina.properties

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
  tag gid: nil
  tag rid: nil
  tag stig_id: 'VCST-70-000028'
  tag fix_id: nil
  tag cci: 'CCI-001762'
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

