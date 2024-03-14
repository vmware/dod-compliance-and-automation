control 'CFLM-5X-000128' do
  title 'The SDDC Manager LCM service must not enable trace information to be displayed.'
  desc  '"Trace" is a technique for a user to request internal information about a server. This is useful during product development, but should not be enabled in production.  Allowing a attacker to conduct a Trace operation against the server will expose information that would be useful to perform a more targeted attack.'
  desc  'rationale', ''
  desc  'check', "
    At the command prompt, run the following command:

    # grep server.error.include-stacktrace /opt/vmware/vcf/lcm/lcm-app/conf/application-prod.properties

    Example result:

    server.error.include-stacktrace=never

    If \"server.error.include-stacktrace\" is not configured to \"never\", this is a finding.
  "
  desc 'fix', "
    Navigate to and open:

    /opt/vmware/vcf/lcm/lcm-app/conf/application-prod.properties

    Add or edit the following line to match below:

    server.error.include-stacktrace=never

    Restart the service for the setting to take effect.

    # systemctl restart lcm.service
  "
  impact 0.5
  tag severity: 'medium'
  tag gtitle: 'SRG-APP-000516-AS-000237'
  tag gid: 'V-CFLM-5X-000128'
  tag rid: 'SV-CFLM-5X-000128'
  tag stig_id: 'CFLM-5X-000128'
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']

  describe parse_config_file(input('applicationProdPropertiesPath')) do
    its(['server.error.include-stacktrace']) { should cmp 'never' }
  end
end
