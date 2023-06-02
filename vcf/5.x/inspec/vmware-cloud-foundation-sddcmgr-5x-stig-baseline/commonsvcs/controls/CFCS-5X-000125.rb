control 'CFCS-5X-000125' do
  title 'The SDDC Manager Common Services service must be configured to only listen on a specified port.'
  desc  'The application server must be configured to listen on a specified IP address and port.  Without specifying an IP address and port for the web server to utilize, the web server will listen on all IP addresses available to the hosting server.'
  desc  'rationale', ''
  desc  'check', "
    At the command prompt, run the following command:

    # grep server.port /opt/vmware/vcf/commonsvcs/conf/application-prod.properties

    Example result:

    server.port=7100

    If \"server.port\" is not configured to \"7100\", this is a finding.
  "
  desc 'fix', "
    Navigate to and open:

    /opt/vmware/vcf/commonsvcs/conf/application-prod.properties

    Add or edit the following line to match below:

    server.port=7100

    Restart the service for the setting to take effect.

    # systemctl restart commonsvcs.service
  "
  impact 0.5
  tag severity: 'medium'
  tag gtitle: 'SRG-APP-000516-AS-000237'
  tag gid: 'V-CFCS-5X-000125'
  tag rid: 'SV-CFCS-5X-000125'
  tag stig_id: 'CFCS-5X-000125'
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']

  describe parse_config_file(input('applicationProdPropertiesPath')) do
    its(['server.port']) { should cmp '7100' }
  end
end
