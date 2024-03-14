control 'CFLM-5X-000126' do
  title 'The SDDC Manager LCM service must not show directory listings.'
  desc  "Enumeration techniques, such as URL parameter manipulation, rely upon being able to obtain information about the server's directory structure by locating directories without default pages. In the scenario, the server will display to the user a listing of the files in the directory being accessed. Ensuring that directory listing is disabled is one approach to mitigating the vulnerability."
  desc  'rationale', ''
  desc  'check', "
    At the command prompt, run the following command:

    # grep server.servlet.jsp.init-parameters.listings /opt/vmware/vcf/lcm/lcm-app/conf/application-prod.properties

    Example result:

    server.servlet.jsp.init-parameters.listings=false

    If \"server.servlet.jsp.init-parameters.listings\" is not configured to \"false\", this is a finding.
  "
  desc 'fix', "
    Navigate to and open:

    /opt/vmware/vcf/lcm/lcm-app/conf/application-prod.properties

    Add or edit the following line to match below:

    server.servlet.jsp.init-parameters.listings=false

    Restart the service for the setting to take effect.

    # systemctl restart lcm.service
  "
  impact 0.5
  tag severity: 'medium'
  tag gtitle: 'SRG-APP-000516-AS-000237'
  tag gid: 'V-CFLM-5X-000126'
  tag rid: 'SV-CFLM-5X-000126'
  tag stig_id: 'CFLM-5X-000126'
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']

  describe parse_config_file(input('applicationProdPropertiesPath')) do
    its(['server.servlet.jsp.init-parameters.listings']) { should cmp 'false' }
  end
end
