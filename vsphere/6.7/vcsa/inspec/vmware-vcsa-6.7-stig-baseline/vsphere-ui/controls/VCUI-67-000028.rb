control 'VCUI-67-000028' do
  title 'vSphere UI must be configured with the appropriate ports.'
  desc  "Web servers provide numerous processes, features, and functionalities
that use TCP/IP ports. Some of these processes may be deemed unnecessary or too
unsecure to run on a production system. The ports that vSphere UI listens on
are configured in the \"catalina.properties\" file and must be verified as
accurate to their shipping state."
  desc  'rationale', ''
  desc  'check', "
    At the command prompt, execute the following command:

    # grep '.port' /usr/lib/vmware-vsphere-ui/server/conf/catalina.properties

    Expected result:

    http.port=5090
    proxy.port=443
    https.port=5443

    If the output of the command does not match the expected result, this is a
finding.
  "
  desc 'fix', "
    Navigate to and open
/usr/lib/vmware-vsphere-ui/server/conf/catalina.properties.

    Navigate to the ports specification section.

    Set the vSphere UI port specifications according to the shipping
configuration below:

    http.port=5090
    proxy.port=443
    https.port=5443
  "
  impact 0.5
  tag severity: 'medium'
  tag gtitle: 'SRG-APP-000383-WSR-000175'
  tag gid: 'V-239709'
  tag rid: 'SV-239709r679233_rule'
  tag stig_id: 'VCUI-67-000028'
  tag fix_id: 'F-42901r679232_fix'
  tag cci: ['CCI-001762']
  tag nist: ['CM-7 (1) (b)']

  describe parse_config_file("#{input('catalinaPropertiesPath')}").params['http.port'] do
    it { should eq "#{input('catalinahttpPort')}" }
  end

  describe parse_config_file("#{input('catalinaPropertiesPath')}").params['proxy.port'] do
    it { should eq "#{input('catalinaproxyPort')}" }
  end
  describe parse_config_file("#{input('catalinaPropertiesPath')}").params['https.port'] do
    it { should eq "#{input('catalinahttpsPort')}" }
  end
end
