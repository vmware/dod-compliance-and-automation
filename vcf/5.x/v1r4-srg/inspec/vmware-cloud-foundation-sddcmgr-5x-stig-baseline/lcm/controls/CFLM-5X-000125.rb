control 'CFLM-5X-000125' do
  title 'The SDDC Manager LCM service must be configured to only listen on a specified port.'
  desc  'The application server must be configured to listen on a specified IP address and port.  Without specifying an IP address and port for the web server to utilize, the web server will listen on all IP addresses available to the hosting server.'
  desc  'rationale', ''
  desc  'check', "
    At the command prompt, run the following command:

    # grep server.port /opt/vmware/vcf/lcm/lcm-app/conf/application-prod.properties

    Example result:

    server.port=7400

    If \"server.port\" is not configured to \"7400\", this is a finding.
  "
  desc 'fix', "
    Navigate to and open:

    /opt/vmware/vcf/lcm/lcm-app/conf/application-prod.properties

    Add or edit the following line to match below:

    server.port=7400

    Restart the service for the setting to take effect.

    # systemctl restart lcm.service
  "
  impact 0.5
  tag severity: 'medium'
  tag gtitle: 'SRG-APP-000516-AS-000237'
  tag gid: 'V-CFLM-5X-000125'
  tag rid: 'SV-CFLM-5X-000125'
  tag stig_id: 'CFLM-5X-000125'
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']

  describe parse_config_file(input('applicationProdPropertiesPath')) do
    its(['server.port']) { should cmp '7400' }
  end
end
