control 'CFLM-4X-000009' do
  title 'LCM must be configured to only listen on a specified port.'
  desc  'The web server must be configured to listen on a specified IP address and port.  Without specifying an IP address and port for the web server to utilize, the web server will listen on all IP addresses available to the hosting server.'
  desc  'rationale', ''
  desc  'check', "
    At the command prompt, run the following command:

    # grep server.port /opt/vmware/vcf/lcm/lcm-app/conf/application-prod.properties

    Expected result:

    server.port=7400

    If the output does not match the expected result or is commented out, this is a finding.
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
  tag gtitle: 'SRG-APP-000142-WSR-000089'
  tag satisfies: ['SRG-APP-000383-WSR-000175']
  tag gid: 'V-CFLM-4X-000009'
  tag rid: 'SV-CFLM-4X-000009'
  tag stig_id: 'CFLM-4X-000009'
  tag cci: ['CCI-000382', 'CCI-001762']
  tag nist: ['CM-7 (1) (b)', 'CM-7 b']

  describe parse_config_file(input('applicationProdPropertiesPath')) do
    its(['server.port']) { should cmp '7400' }
  end
end
