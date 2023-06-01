control 'CFLM-5X-000131' do
  title 'The SDDC Manager LCM service must be protected from being stopped.'
  desc  "
    An attacker has at least two reasons to stop an application server. The first is to cause a DoS, and the second is to put in place changes the attacker made to the server configuration.

    To prohibit an attacker from stopping the web server, the process ID (pid) of the server and the utilities used to start/stop the server must be protected from access by non-privileged users. By knowing the pid and having access to the web server utilities, a non-privileged user has a greater capability of stopping the server, whether intentionally or unintentionally.
  "
  desc  'rationale', ''
  desc  'check', "
    At the command prompt, run the following command:

    # grep management.endpoint.shutdown.enabled /opt/vmware/vcf/lcm/lcm-app/conf/application-prod.properties

    Example result:

    management.endpoint.shutdown.enabled=false

    If \"management.endpoint.shutdown.enabled\" is not configured to \"false\", this is a finding.
  "
  desc 'fix', "
    Navigate to and open:

    /opt/vmware/vcf/lcm/lcm-app/conf/application-prod.properties

    Add or edit the following line to match below:

    management.endpoint.shutdown.enabled=false

    Restart the service for the setting to take effect.

    # systemctl restart lcm.service
  "
  impact 0.5
  tag severity: 'medium'
  tag gtitle: 'SRG-APP-000516-AS-000237'
  tag gid: 'V-CFLM-5X-000131'
  tag rid: 'SV-CFLM-5X-000131'
  tag stig_id: 'CFLM-5X-000131'
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']

  describe parse_config_file(input('applicationProdPropertiesPath')) do
    its(['management.endpoint.shutdown.enabled']) { should cmp 'false' }
  end
end
