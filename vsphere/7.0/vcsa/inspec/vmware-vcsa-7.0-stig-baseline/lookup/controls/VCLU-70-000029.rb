control 'VCLU-70-000029' do
  title 'Lookup Service must must be configured with the appropriate ports.'
  desc  'Web servers provide numerous processes, features, and functionalities that use TCP/IP ports. Some of these processes may be deemed unnecessary or too unsecure to run on a production system. The ports that Lookup Service listens on are configured in the "catalina.properties" file and must be veriified as accurate to their shipping state.'
  desc  'rationale', ''
  desc  'check', "
    At the command prompt, execute the following command:

    # grep '\\.port' /usr/lib/vmware-lookupsvc/conf/catalina.properties

    Expected result:

    base.shutdown.port=-1
    base.jmx.port=-1
    bio-custom.http.port=7090
    bio-custom.https.port=8443

    If the output of the command does not match the expected result, this is a finding.
  "
  desc 'fix', "
    Navigate to and open:

    /usr/lib/vmware-lookupsvc/conf/catalina.properties

    Navigate to the ports specification section.

    Set the Lookup Service port specifications according to the shipping configuration below:

    base.shutdown.port=-1
    base.jmx.port=-1
    bio-custom.http.port=7090
    bio-custom.https.port=8443

    Restart the service with the following command:

    # vmon-cli --restart lookupsvc
  "
  impact 0.5
  tag severity: 'medium'
  tag gtitle: 'SRG-APP-000383-WSR-000175'
  tag gid: nil
  tag rid: nil
  tag stig_id: 'VCLU-70-000029'
  tag cci: ['CCI-001762']
  tag nist: ['CM-7 (1) (b)']

  describe parse_config_file("#{input('catalinaPropertiesPath')}").params['base.shutdown.port'] do
    it { should eq "#{input('catalinashutdownPort')}" }
  end

  describe parse_config_file("#{input('catalinaPropertiesPath')}").params['base.jmx.port'] do
    it { should eq "#{input('catalinajmxPort')}" }
  end

  describe parse_config_file("#{input('catalinaPropertiesPath')}").params['bio-custom.http.port'] do
    it { should eq "#{input('catalinahttpPort')}" }
  end

  describe parse_config_file("#{input('catalinaPropertiesPath')}").params['bio-custom.https.port'] do
    it { should eq "#{input('catalinahttpsPort')}" }
  end
end
