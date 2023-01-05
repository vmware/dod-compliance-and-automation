control 'CFLM-4X-000008' do
  title 'The SDDC Manager LCM service must be configured to only listen on the loopback address.'
  desc  "
    The web server must be configured to listen on a specified IP address and port.  Without specifying an IP address and port for the web server to utilize, the web server will listen on all IP addresses available to the hosting server.

    Web servers behind a reverse proxy should not listen on externally accessible addresses.
  "
  desc  'rationale', ''
  desc  'check', "
    At the command prompt, run the following command:

    # grep server.address /opt/vmware/vcf/lcm/lcm-app/conf/application-prod.properties

    Expected result:

    server.address=127.0.0.1

    If the output does not match the expected result or is commented out, this is a finding.
  "
  desc 'fix', "
    Navigate to and open:

    /opt/vmware/vcf/lcm/lcm-app/conf/application-prod.properties

    Add or edit the following line to match below:

    server.address=127.0.0.1

    Restart the service for the setting to take effect.

    # systemctl restart lcm.service
  "
  impact 0.3
  tag severity: 'low'
  tag gtitle: 'SRG-APP-000142-WSR-000089'
  tag gid: nil
  tag rid: nil
  tag stig_id: 'CFLM-4X-000008'
  tag cci: ['CCI-000382']
  tag nist: ['CM-7 b']

  describe parse_config_file(input('applicationProdPropertiesPath')) do
    its(['server.address']) { should cmp '127.0.0.1' }
  end
end
