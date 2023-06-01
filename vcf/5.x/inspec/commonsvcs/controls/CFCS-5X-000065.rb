control 'CFCS-5X-000065' do
  title 'The SDDC Manager Common Services service must check the validity of all data inputs.'
  desc  "
    Invalid user input occurs when a user inserts data or characters into an applications data entry field and the application is unprepared to process that data. This results in unanticipated application behavior potentially leading to an application or information system compromise. Invalid user input is one of the primary methods employed when attempting to compromise an application.

    Application servers must ensure their management interfaces perform data input validation checks. Input validation consists of evaluating user input and ensuring that only allowed characters are utilized. An example is ensuring that the interfaces are not susceptible to SQL injection attacks.
  "
  desc  'rationale', ''
  desc  'check', "
    At the command prompt, run the following command:

    # grep server.tomcat.uri-encoding /opt/vmware/vcf/commonsvcs/conf/application-prod.properties

    Example result:

    server.tomcat.uri-encoding=UTF-8

    If \"server.tomcat.uri-encoding\" is not configured to \"UTF-8\", this is a finding.
  "
  desc 'fix', "
    Navigate to and open:

    /opt/vmware/vcf/commonsvcs/conf/application-prod.properties

    Add or edit the following line to match below:

    server.tomcat.uri-encoding=UTF-8

    Restart the service for the setting to take effect.

    # systemctl restart commonsvcs.service
  "
  impact 0.5
  tag severity: 'medium'
  tag gtitle: 'SRG-APP-000251-AS-000165'
  tag gid: 'V-CFCS-5X-000065'
  tag rid: 'SV-CFCS-5X-000065'
  tag stig_id: 'CFCS-5X-000065'
  tag cci: ['CCI-001310']
  tag nist: ['SI-10']

  describe parse_config_file(input('applicationProdPropertiesPath')) do
    its(['server.tomcat.uri-encoding']) { should cmp 'UTF-8' }
  end
end
