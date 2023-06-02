control 'CFCS-5X-000124' do
  title 'The SDDC Manager Common Services service must be configured to only listen on the loopback address.'
  desc  "
    The application server must be configured to listen on a specified IP address and port.  Without specifying an IP address and port for the web server to utilize, the web server will listen on all IP addresses available to the hosting server.

    Application servers behind a reverse proxy should not listen on externally accessible addresses.
  "
  desc  'rationale', ''
  desc  'check', "
    At the command prompt, run the following command:

    # grep server.address /opt/vmware/vcf/commonsvcs/conf/application-prod.properties

    Example result:

    server.address=localhost

    If \"server.address\" is not configured to \"localhost\", this is a finding.
  "
  desc 'fix', "
    Navigate to and open:

    /opt/vmware/vcf/commonsvcs/conf/application-prod.properties

    Add or edit the following line to match below:

    server.address=localhost

    Restart the service for the setting to take effect.

    # systemctl restart commonsvcs.service
  "
  impact 0.5
  tag severity: 'medium'
  tag gtitle: 'SRG-APP-000516-AS-000237'
  tag gid: 'V-CFCS-5X-000124'
  tag rid: 'SV-CFCS-5X-000124'
  tag stig_id: 'CFCS-5X-000124'
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']

  describe parse_config_file(input('applicationProdPropertiesPath')) do
    its(['server.address']) { should cmp 'localhost' }
  end
end
