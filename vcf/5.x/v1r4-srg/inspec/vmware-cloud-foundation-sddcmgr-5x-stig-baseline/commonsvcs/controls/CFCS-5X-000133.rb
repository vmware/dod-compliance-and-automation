control 'CFCS-5X-000133' do
  title 'The SDDC Manager Common Services service must block clients after a number of failed attempts to gain an API token.'
  desc  'By limiting the number of failed logon attempts, the risk of unauthorized system access via user password guessing, otherwise known as brute-force attacks, is reduced. Limits are imposed by blocking the client IP for 1 day after a number of failed attempts to obtain an API token.'
  desc  'rationale', ''
  desc  'check', "
    At the command prompt, run the following command:

    # grep wrong.password.max.attempt /opt/vmware/vcf/commonsvcs/conf/application-prod.properties

    Example result:

    wrong.password.max.attempt=10

    If \"wrong.password.max.attempt\" is not set to \"10\", this is a finding.
  "
  desc 'fix', "
    Navigate to and open:

    /opt/vmware/vcf/commonsvcs/conf/application-prod.properties

    Add or edit the following lines to match below:

    wrong.password.max.attempt=10

    Restart the service for the setting to take effect.

    # systemctl restart commonsvcs.service
  "
  impact 0.5
  tag severity: 'medium'
  tag gtitle: 'SRG-APP-000516-AS-000237'
  tag gid: 'V-CFCS-5X-000133'
  tag rid: 'SV-CFCS-5X-000133'
  tag stig_id: 'CFCS-5X-000133'
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']

  describe parse_config_file(input('applicationProdPropertiesPath')) do
    its(['wrong.password.max.attempt']) { should cmp '10' }
  end
end
