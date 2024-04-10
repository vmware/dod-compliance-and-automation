control 'VRPU-8X-000057' do
  title 'The VMware Aria Operations UI service must be configured to limit data exposure between applications.'
  desc  'If RECYCLE_FACADES is true or if a security manager is in use, a new facade object will be created for each request. This reduces the chances that a bug in an application might expose data from one request to another.'
  desc  'rationale', ''
  desc  'check', "
    At the command line, run the following command:

    # grep RECYCLE_FACADES /usr/lib/vmware-vcops/tomcat-web-app/conf/catalina.properties

    Example result:

    org.apache.catalina.connector.RECYCLE_FACADES=true

    If \"org.apache.catalina.connector.RECYCLE_FACADES\" is not set to \"true\", this is a finding.
  "
  desc 'fix', "
    Navigate to and open the /usr/lib/vmware-vcops/tomcat-web-app/conf/catalina.properties file.

    Add or update the following line:

    org.apache.catalina.connector.RECYCLE_FACADES=true

    Restart the service with the following command:

    # systemctl restart vmware-vcops-web.service
  "
  impact 0.5
  tag severity: 'medium'
  tag gtitle: 'SRG-APP-000223-AS-000150'
  tag satisfies: ['SRG-APP-000516-AS-000237']
  tag gid: 'V-VRPU-8X-000057'
  tag rid: 'SV-VRPU-8X-000057'
  tag stig_id: 'VRPU-8X-000057'
  tag cci: ['CCI-000366', 'CCI-001664']
  tag nist: ['CM-6 b', 'SC-23 (3)']

  describe parse_config_file("#{input('ui-catalinaPropsPath')}").params['org.apache.catalina.connector.RECYCLE_FACADES'] do
    it { should cmp 'true' }
  end
end
