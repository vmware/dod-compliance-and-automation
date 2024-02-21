control 'VRLT-8X-000062' do
  title 'The VMware Aria Operations for Logs tc Server must be built to fail to a known safe state if system initialization fails, shutdown fails, or aborts fail.'
  desc  'Determining a safe state for failure and weighing that against a potential denial of service for users depends on what type of application the tc Server is hosting. In most cases, it is preferable that the service abort startup on any initialization failure rather than continuing in a degraded, and potentially insecure, state.'
  desc  'rationale', ''
  desc  'check', "
    At the command prompt, run the following commands:

    # grep -i EXIT_ON_INIT_FAILURE /usr/lib/loginsight/application/3rd_party/apache-tomcat/conf/catalina.properties

    If the setting org.apache.catalina.startup.EXIT_ON_INIT_FAILURE is false, or is missing from the file, this is a finding.
  "
  desc 'fix', "
    Edit the /usr/lib/loginsight/application/3rd_party/apache-tomcat/conf/catalina.properties file.

    Add or change the org.apache.catalina.startup.EXIT_ON_INIT_FAILURE setting to equal true.

    Restart the service:
    # systemctl restart loginsight.service
  "
  impact 0.5
  tag severity: 'medium'
  tag gtitle: 'SRG-APP-000225-AS-000166'
  tag gid: 'V-VRLT-8X-000062'
  tag rid: 'SV-VRLT-8X-000062'
  tag stig_id: 'VRLT-8X-000062'
  tag cci: ['CCI-001190']
  tag nist: ['SC-24']
  props = parse_config(file("#{input('catalinaBase')}/conf/catalina.properties").content)

  describe props do
    its(['org.apache.catalina.startup.EXIT_ON_INIT_FAILURE']) { should cmp 'true' }
  end
end
