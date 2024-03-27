control 'WOAT-3X-000093' do
  title 'Workspace ONE Access must disable the shutdown port.'
  desc  'An attacker has at least two reasons to stop a web server. The first is to cause a DoS, and the second is to put in place changes the attacker made to the web server configuration. If the Tomcat shutdown port feature is enabled, a shutdown signal can be sent to the horizon-workspace through this port. To ensure availability, the shutdown port must be disabled.'
  desc  'rationale', ''
  desc  'check', "
    At the command prompt, execute the following command:

    # grep 'base.shutdown.port' /opt/vmware/horizon/workspace/conf/catalina.properties

    Expected result:

    base.shutdown.port=-1

    If the output of the command does not match the expected result, this is a finding.
  "
  desc 'fix', "
    Navigate to and open:

    /opt/vmware/horizon/workspace/conf/catalina.properties

    Add or modify the following setting:

    base.shutdown.port=-1
  "
  impact 0.5
  tag severity: 'medium'
  tag gtitle: 'SRG-APP-000435-WSR-000147'
  tag gid: 'V-WOAT-3X-000093'
  tag rid: 'SV-WOAT-3X-000093'
  tag stig_id: 'WOAT-3X-000093'
  tag cci: ['CCI-002385']
  tag nist: ['SC-5']

  describe parse_config_file("#{input('catalinaPropertiesPath')}") do
    its(['base.shutdown.port']) { should cmp '-1' }
  end
end
