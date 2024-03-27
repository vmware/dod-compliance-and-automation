control 'CFLM-5X-000127' do
  title 'The SDDC Manager LCM service must minimize information displayed in error messages.'
  desc  "
    Information needed by an attacker to begin looking for possible vulnerabilities in a server includes any information about the server, backend systems being accessed, and plug-ins or modules being used.

    Application servers will often display error messages to client users displaying enough information to aid in the debugging of the error. The information given back in error messages may display the web server type, version, patches installed, plug-ins and modules installed, type of code being used by the hosted application, and any backends being used for data storage.

    This information could be used by an attacker to blueprint what type of attacks might be successful. The information given to users must be minimized to not aid in the blueprinting of the server.
  "
  desc  'rationale', ''
  desc  'check', "
    At the command prompt, run the following command:

    # grep server.error.whitelabel.enabled /opt/vmware/vcf/lcm/lcm-app/conf/application-prod.properties

    Example result:

    server.error.whitelabel.enabled=false

    If \"server.error.whitelabel.enabled\" is not configured to \"false\", this is a finding.
  "
  desc 'fix', "
    Navigate to and open:

    /opt/vmware/vcf/lcm/lcm-app/conf/application-prod.properties

    Add or edit the following line to match below:

    server.error.whitelabel.enabled=false

    Restart the service for the setting to take effect.

    # systemctl restart lcm.service
  "
  impact 0.5
  tag severity: 'medium'
  tag gtitle: 'SRG-APP-000516-AS-000237'
  tag gid: 'V-CFLM-5X-000127'
  tag rid: 'SV-CFLM-5X-000127'
  tag stig_id: 'CFLM-5X-000127'
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']

  describe parse_config_file(input('applicationProdPropertiesPath')) do
    its(['server.error.whitelabel.enabled']) { should cmp 'false' }
  end
end
