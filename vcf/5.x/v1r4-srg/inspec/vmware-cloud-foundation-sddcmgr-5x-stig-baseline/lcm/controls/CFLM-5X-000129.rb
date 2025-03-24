control 'CFLM-5X-000129' do
  title 'The SDDC Manager LCM service must not enable debug information to be displayed.'
  desc  'Information needed by an attacker to begin looking for possible vulnerabilities in a server includes any information about the server and plug-ins or modules being used. When debugging or trace information is enabled in a production server, information about the server, such as server type, version, patches installed, plug-ins and modules installed, type of code being used by the hosted application, and any backends being used for data storage may be displayed. Since this information may be placed in logs and general messages during normal operation of the web server, an attacker does not need to cause an error condition to gain this information.'
  desc  'rationale', ''
  desc  'check', "
    At the command prompt, run the following command:

    # grep server.servlet.jsp.init-parameters.debug /opt/vmware/vcf/lcm/lcm-app/conf/application-prod.properties

    Example result:

    server.servlet.jsp.init-parameters.debug=0

    If \"server.servlet.jsp.init-parameters.debug\" is not configured to \"0\", this is a finding.
  "
  desc 'fix', "
    Navigate to and open:

    /opt/vmware/vcf/lcm/lcm-app/conf/application-prod.properties

    Add or edit the following line to match below:

    server.servlet.jsp.init-parameters.debug=0

    Restart the service for the setting to take effect.

    # systemctl restart lcm.service
  "
  impact 0.5
  tag severity: 'medium'
  tag gtitle: 'SRG-APP-000516-AS-000237'
  tag gid: 'V-CFLM-5X-000129'
  tag rid: 'SV-CFLM-5X-000129'
  tag stig_id: 'CFLM-5X-000129'
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']

  describe parse_config_file(input('applicationProdPropertiesPath')) do
    its(['server.servlet.jsp.init-parameters.debug']) { should cmp '0' }
  end
end
