control 'VCLU-80-000057' do
  title 'The vCenter Lookup service must be configured to limit data exposure between applications.'
  desc  'If RECYCLE_FACADES is true or if a security manager is in use, a new facade object will be created for each request. This reduces the chances that a bug in an application might expose data from one request to another.'
  desc  'rationale', ''
  desc  'check', "
    At the command line, run the following command:

    # grep RECYCLE_FACADES /usr/lib/vmware-lookupsvc/conf/catalina.properties

    Example result:

    org.apache.catalina.connector.RECYCLE_FACADES=true

    If \"org.apache.catalina.connector.RECYCLE_FACADES\" is not set to \"true\", this is a finding.

    If the \"org.apache.catalina.connector.RECYCLE_FACADES\" setting does not exist, this is not a finding.
  "
  desc 'fix', "
    Navigate to and open:

    /usr/lib/vmware-lookupsvc/conf/catalina.properties

    Update or remove the following line:

    org.apache.catalina.connector.RECYCLE_FACADES=true

    Restart the service with the following command:

    # vmon-cli --restart lookupsvc
  "
  impact 0.5
  tag severity: 'medium'
  tag gtitle: 'SRG-APP-000223-AS-000150'
  tag gid: 'V-VCLU-80-000057'
  tag rid: 'SV-VCLU-80-000057'
  tag stig_id: 'VCLU-80-000057'
  tag cci: ['CCI-001664']
  tag nist: ['SC-23 (3)']

  describe parse_config_file("#{input('catalinaPropertiesPath')}").params['org.apache.catalina.connector.RECYCLE_FACADES'] do
    it { should be_in [nil, 'true'] }
  end
end
