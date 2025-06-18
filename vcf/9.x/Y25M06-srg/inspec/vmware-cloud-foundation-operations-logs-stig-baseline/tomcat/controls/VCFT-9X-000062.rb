control 'VCFT-9X-000062' do
  title 'The VMware Cloud Foundation Operations for Logs Loginsight service must fail to a secure state if system initialization fails, shutdown fails, or aborts fail.'
  desc  'Fail-secure is a condition achieved by the application server in order to ensure that in the event of an operational failure, the system does not enter into an unsecure state where intended security properties no longer hold.  Preserving system state information also facilitates system restart and return to the operational mode of the organization with less disruption of mission-essential processes.'
  desc  'rationale', ''
  desc  'check', "
    At the command prompt, run the following:

    # grep -i EXIT_ON_INIT_FAILURE /usr/lib/loginsight/application/3rd_party/apache-tomcat/conf/catalina.properties

    Example result:

    org.apache.catalina.startup.EXIT_ON_INIT_FAILURE=true

    If there are no results, or if the \"org.apache.catalina.startup.EXIT_ON_INIT_FAILURE\" is not set to \"true\", this is a finding.
  "
  desc 'fix', "
    Navigate to and open:

    /usr/lib/loginsight/application/3rd_party/apache-tomcat/conf/catalina.properties

    Add or change the following line:

    org.apache.catalina.startup.EXIT_ON_INIT_FAILURE=true

    Restart the service with the following command:

    # systemctl restart loginsight.service
  "
  impact 0.5
  tag severity: 'medium'
  tag gtitle: 'SRG-APP-000225-AS-000166'
  tag gid: 'V-VCFT-9X-000062'
  tag rid: 'SV-VCFT-9X-000062'
  tag stig_id: 'VCFT-9X-000062'
  tag cci: ['CCI-001190']
  tag nist: ['SC-24']

  result = parse_config_file("#{input('catalinaBase')}/conf/catalina.properties").params['org.apache.catalina.startup.EXIT_ON_INIT_FAILURE']

  describe 'org.apache.catalina.startup.EXIT_ON_INIT_FAILURE' do
    subject { result }
    it { should cmp 'true' }
  end
end
