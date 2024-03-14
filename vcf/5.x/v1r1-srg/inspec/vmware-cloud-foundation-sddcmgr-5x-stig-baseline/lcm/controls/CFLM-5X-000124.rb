control 'CFLM-5X-000124' do
  title 'The SDDC Manager LCM service must be configured to only listen on the loopback address.'
  desc  "
    The application server must be configured to listen on a specified IP address and port.  Without specifying an IP address and port for the web server to utilize, the web server will listen on all IP addresses available to the hosting server.

    Application servers behind a reverse proxy should not listen on externally accessible addresses.
  "
  desc  'rationale', ''
  desc  'check', "
    At the command prompt, run the following command:

    # grep server.address /opt/vmware/vcf/lcm/lcm-app/conf/application-prod.properties

    Example result:

    server.address=127.0.0.1

    If \"server.address\" is not configured to \"127.0.0.1\" or \"localhost\", this is a finding.
  "
  desc 'fix', "
    Navigate to and open:

    /opt/vmware/vcf/lcm/lcm-app/conf/application-prod.properties

    Add or edit the following line to match below:

    server.address=127.0.0.1

    Restart the service for the setting to take effect.

    # systemctl restart lcm.service
  "
  impact 0.5
  tag severity: 'medium'
  tag gtitle: 'SRG-APP-000516-AS-000237'
  tag gid: 'V-CFLM-5X-000124'
  tag rid: 'SV-CFLM-5X-000124'
  tag stig_id: 'CFLM-5X-000124'
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']

  describe parse_config_file(input('applicationProdPropertiesPath')) do
    its(['server.address']) { should cmp '127.0.0.1' }
  end
end
