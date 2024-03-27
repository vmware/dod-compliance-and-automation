control 'CFLM-4X-000012' do
  title 'The SDDC Manager LCM service must not show directory listings.'
  desc  "Enumeration techniques, such as URL parameter manipulation, rely upon being able to obtain information about the web server's directory structure by locating directories without default pages. In the scenario, the web server will display to the user a listing of the files in the directory being accessed. Ensuring that directory listing is disabled is one approach to mitigating the vulnerability."
  desc  'rationale', ''
  desc  'check', "
    At the command prompt, run the following command:

    # grep server.servlet.jsp.init-parameters.listings /opt/vmware/vcf/lcm/lcm-app/conf/application-prod.properties

    Expected result:

    server.servlet.jsp.init-parameters.listings=false

    If the output does not match the expected result or is commented out, this is a finding.
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
  tag gtitle: 'SRG-APP-000266-WSR-000142'
  tag gid: nil
  tag rid: nil
  tag stig_id: 'CFLM-4X-000012'
  tag cci: ['CCI-001312']
  tag nist: ['SI-11 a']

  describe parse_config_file(input('applicationProdPropertiesPath')) do
    its(['server.servlet.jsp.init-parameters.listings']) { should cmp 'false' }
  end
end
