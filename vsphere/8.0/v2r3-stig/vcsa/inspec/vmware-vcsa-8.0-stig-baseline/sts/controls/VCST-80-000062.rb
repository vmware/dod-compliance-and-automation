control 'VCST-80-000062' do
  title 'The vCenter STS service must be configured to fail to a known safe state if system initialization fails.'
  desc 'Determining a safe state for failure and weighing that against a potential denial of service for users depends on what type of application the web server is hosting. It is preferable that the service abort startup on any initialization failure rather than continuing in a degraded, and potentially insecure, state.'
  desc 'check', 'At the command line, run the following command:

# grep EXIT_ON_INIT_FAILURE /usr/lib/vmware-sso/vmware-sts/conf/catalina.properties

Example result:

org.apache.catalina.startup.EXIT_ON_INIT_FAILURE=true

If there are no results, or if the "org.apache.catalina.startup.EXIT_ON_INIT_FAILURE" is not set to "true", this is a finding.'
  desc 'fix', 'Navigate to and open:

/usr/lib/vmware-sso/vmware-sts/conf/catalina.properties

Add or change the following line:

org.apache.catalina.startup.EXIT_ON_INIT_FAILURE=true

Restart the service with the following command:

# vmon-cli --restart sts'
  impact 0.5
  tag check_id: 'C-62720r934596_chk'
  tag severity: 'medium'
  tag gid: 'V-258980'
  tag rid: 'SV-258980r961122_rule'
  tag stig_id: 'VCST-80-000062'
  tag gtitle: 'SRG-APP-000225-AS-000166'
  tag fix_id: 'F-62629r934597_fix'
  tag cci: ['CCI-001190']
  tag nist: ['SC-24']

  describe parse_config_file("#{input('catalinaPropertiesPath')}").params['org.apache.catalina.startup.EXIT_ON_INIT_FAILURE'] do
    it { should cmp 'true' }
  end
end
