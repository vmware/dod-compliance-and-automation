control 'VRPS-8X-000062' do
  title 'The VMware Aria Operations Casa service must be built to fail to a known safe state if system initialization fails, shutdown fails, or aborts fail.'
  desc  'Determining a safe state for failure and weighing that against a potential denial of service for users depends on what type of application the web server is hosting. In most cases, it is preferable that the service abort startup on any initialization failure rather than continuing in a degraded, and potentially insecure, state.'
  desc  'rationale', ''
  desc  'check', "
    At the command prompt, run the following commands:

    # grep -i EXIT_ON_INIT_FAILURE /usr/lib/vmware-casa/casa-webapp/conf/catalina.properties

    Example result:

    org.apache.catalina.startup.EXIT_ON_INIT_FAILURE=true

    If there are no results, or if the \"org.apache.catalina.startup.EXIT_ON_INIT_FAILURE\" is not set to \"true\", this is a finding.
  "
  desc 'fix', "
    Navigate to and open the /usr/lib/vmware-casa/casa-webapp/conf/catalina.properties file.

    Add or change the following line:

    org.apache.catalina.startup.EXIT_ON_INIT_FAILURE=true

    Restart the service with the following command:

    # systemctl restart vmware-casa.service
  "
  impact 0.5
  tag severity: 'medium'
  tag gtitle: 'SRG-APP-000225-AS-000166'
  tag gid: 'V-VRPS-8X-000062'
  tag rid: 'SV-VRPS-8X-000062'
  tag stig_id: 'VRPS-8X-000062'
  tag cci: ['CCI-001190']
  tag nist: ['SC-24']

  describe parse_config_file("#{input('casa-catalinaPropsPath')}").params['org.apache.catalina.startup.EXIT_ON_INIT_FAILURE'] do
    it { should cmp 'true' }
  end
end
