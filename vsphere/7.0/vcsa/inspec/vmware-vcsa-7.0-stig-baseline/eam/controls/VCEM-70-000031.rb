control 'VCEM-70-000031' do
  title 'ESX Agent Manager must be configured with the appropriate ports.'
  desc  'Web servers provide numerous processes, features, and functionalities that use TCP/IP ports. Some of these processes may be deemed unnecessary or too unsecure to run on a production system. The ports that the ESX Agent Manager listens on are configured in the "catalina.properties" file and must be veriified as accurate to their shipping state.'
  desc  'rationale', ''
  desc  'check', "
    At the command prompt, execute the following command:

    # grep 'bio.http.port' /etc/vmware-eam/catalina.properties

    Expected result:

    bio.http.port=15005

    If the output of the command does not match the expected result, this is a finding.

  "
  desc 'fix', "
    Navigate to and open:

    /etc/vmware-eam/catalina.properties

    Navigate to the ports specification section.

    Set the ESX Agent Manager port specifications according to the following:

    bio.http.port=15005

    Restart the service with the following command:

    # vmon-cli --restart eam
  "
  impact 0.5
  tag severity: 'medium'
  tag gtitle: 'SRG-APP-000383-WSR-000175'
  tag gid: nil
  tag rid: nil
  tag stig_id: 'VCEM-70-000031'
  tag cci: ['CCI-001762']
  tag nist: ['CM-7 (1) (b)']

  describe parse_config_file("#{input('catalinaPropertiesPath')}").params['bio.http.port'] do
    it { should eq "#{input('httpPort')}" }
  end
end
