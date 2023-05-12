control 'CFLM-4X-000011' do
  title 'The SDDC Manager LCM service must set URI encoding to UTF-8.'
  desc  "
    Invalid user input occurs when a user inserts data or characters into a hosted application's data entry field and the hosted application is unprepared to process that data. This results in unanticipated application behavior, potentially leading to an application compromise. Invalid user input is one of the primary methods employed when attempting to compromise an application.

    An attacker can also enter Unicode characters into hosted applications in an effort to break out of the document home or root home directory or to bypass security checks. vSphere UI must be configured to use a consistent character set via the URIEncoding attribute on the Connector nodes.
  "
  desc  'rationale', ''
  desc  'check', "
    At the command prompt, run the following command:

    # grep server.tomcat.uri-encoding /opt/vmware/vcf/lcm/lcm-app/conf/application-prod.properties

    Expected result:

    server.tomcat.uri-encoding=UTF-8

    If the output does not match the expected result or is commented out, this is a finding.
  "
  desc 'fix', "
    Navigate to and open:

    /opt/vmware/vcf/lcm/lcm-app/conf/application-prod.properties

    Add or edit the following line to match below:

    server.tomcat.uri-encoding=UTF-8

    Restart the service for the setting to take effect.

    # systemctl restart lcm.service
  "
  impact 0.5
  tag severity: 'medium'
  tag gtitle: 'SRG-APP-000251-WSR-000157'
  tag gid: 'V-CFLM-4X-000011'
  tag rid: 'SV-CFLM-4X-000011'
  tag stig_id: 'CFLM-4X-000011'
  tag cci: ['CCI-001310']
  tag nist: ['SI-10']

  describe parse_config_file(input('applicationProdPropertiesPath')) do
    its(['server.tomcat.uri-encoding']) { should cmp 'UTF-8' }
  end
end
