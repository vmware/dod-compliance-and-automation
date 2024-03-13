control 'WOAT-3X-000089' do
  title 'Workspace ONE Access must be configured with the appropriate ports.'
  desc  'Web servers provide numerous processes, features, and functionalities that utilize TCP/IP ports. Some of these processes may be deemed unnecessary or too unsecure to run on a production system. The ports that the horizon-workspace listens on are configured in the catalina.properties file and must be veriified as accurate to their shipping state.'
  desc  'rationale', ''
  desc  'check', "
    At the command prompt, execute the following command:

    # grep port /opt/vmware/horizon/workspace/conf/catalina.properties|grep -v shutdown

    Expected result:

    base.jmx.port=6969
    nio-ssl.https.port=6443
    http.port=8080
    https.passthrough.port=7443

    If the output of the command does not match the expected result, this is a finding.
  "
  desc 'fix', "
    Navigate to and open:

    /opt/vmware/horizon/workspace/conf/catalina.properties

    Ensure that the following settings are present and accurate:

    base.jmx.port=6969
    nio-ssl.https.port=6443
    http.port=8080
    https.passthrough.port=7443
  "
  impact 0.5
  tag severity: 'medium'
  tag gtitle: 'SRG-APP-000383-WSR-000175'
  tag gid: 'V-WOAT-3X-000089'
  tag rid: 'SV-WOAT-3X-000089'
  tag stig_id: 'WOAT-3X-000089'
  tag cci: ['CCI-001762']
  tag nist: ['CM-7 (1) (b)']

  describe parse_config_file("#{input('catalinaPropertiesPath')}") do
    its(['base.jmx.port']) { should cmp '6969' }
    its(['nio-ssl.https.port']) { should cmp '6443' }
    its(['http.port']) { should cmp '8080' }
    its(['https.passthrough.port']) { should cmp '7443' }
  end
end
