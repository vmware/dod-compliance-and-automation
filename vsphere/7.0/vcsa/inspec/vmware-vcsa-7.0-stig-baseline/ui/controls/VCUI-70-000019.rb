control 'VCUI-70-000019' do
  title 'vSphere UI must fail to a known safe state if system initialization fails, shutdown fails, or aborts fail.'
  desc  'Determining a safe state for failure and weighing that against a potential denial of service for users depends on what type of application the web server is hosting. For the Security Token Service, it is preferable that the service abort startup on any initialization failure rather than continuing in a degraded, and potentailly insecure, state.'
  desc  'rationale', ''
  desc  'check', "
    At the command line, execute the following command:

    # grep EXIT_ON_INIT_FAILURE /usr/lib/vmware-vsphere-ui/server/conf/catalina.properties

    Expected result :

    org.apache.catalina.startup.EXIT_ON_INIT_FAILURE=true

    If the output of the command does not match the expected result, this is a finding.
  "
  desc 'fix', "
    Navigate to and open:

    /usr/lib/vmware-vsphere-ui/server/conf/catalina.properties

    Add or change the following line:

    org.apache.catalina.startup.EXIT_ON_INIT_FAILURE=true

    Restart the service with the following command:

    # vmon-cli --restart vsphere-ui
  "
  impact 0.5
  tag severity: 'medium'
  tag gtitle: 'SRG-APP-000225-WSR-000140'
  tag gid: nil
  tag rid: nil
  tag stig_id: 'VCUI-70-000019'
  tag cci: ['CCI-001190']
  tag nist: ['SC-24']

  describe parse_config_file("#{input('catalinaPropertiesPath')}").params['org.apache.catalina.startup.EXIT_ON_INIT_FAILURE'] do
    it { should eq 'true' }
  end
end
