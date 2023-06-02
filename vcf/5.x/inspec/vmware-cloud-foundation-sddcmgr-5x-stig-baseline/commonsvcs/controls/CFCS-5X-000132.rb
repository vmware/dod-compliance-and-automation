control 'CFCS-5X-000132' do
  title 'The SDDC Manager Common Services service must restrict the number of failed attempts for the local API account.'
  desc  'A local account is used to access VMware Cloud Foundation APIs when the management vCenter Server is down. By limiting the number of failed logon attempts, the risk of unauthorized system access via user password guessing, otherwise known as brute-force attacks, is reduced. Limits are imposed by locking the account.'
  desc  'rationale', ''
  desc  'check', "
    At the command prompt, run the following command:

    # grep local.account /opt/vmware/vcf/commonsvcs/conf/application-prod.properties

    Example result:

    local.account.unlock.time.minutes=30
    local.account.max.failed.attempt=3

    If \"local.account.unlock.time.minutes\" is not configured to \"30\" or more, this is a finding.
    If \"local.account.max.failed.attempt\" is not configured to \"3\", this is a finding.
  "
  desc 'fix', "
    Navigate to and open:

    /opt/vmware/vcf/commonsvcs/conf/application-prod.properties

    Add or edit the following lines to match below:

    local.account.unlock.time.minutes=30
    local.account.max.failed.attempt=3

    Restart the service for the setting to take effect.

    # systemctl restart commonsvcs.service
  "
  impact 0.5
  tag severity: 'medium'
  tag gtitle: 'SRG-APP-000516-AS-000237'
  tag gid: 'V-CFCS-5X-000132'
  tag rid: 'SV-CFCS-5X-000132'
  tag stig_id: 'CFCS-5X-000132'
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']

  describe parse_config_file(input('applicationProdPropertiesPath')) do
    its(['local.account.unlock.time.minutes']) { should cmp >= 30 }
    its(['local.account.max.failed.attempt']) { should cmp '3' }
  end
end
