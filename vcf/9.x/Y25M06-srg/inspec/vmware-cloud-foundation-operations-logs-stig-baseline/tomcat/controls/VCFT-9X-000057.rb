control 'VCFT-9X-000057' do
  title 'The VMware Cloud Foundation Operations for Logs Loginsight service must be configured to limit data exposure between applications.'
  desc  'If RECYCLE_FACADES is true or if a security manager is in use, a new facade object will be created for each request. This reduces the chances that a bug in an application might expose data from one request to another. This setting is configured using environment variable settings. For Linux OS flavors other than Ubuntu, use the relevant OS commands. For Ubuntu, this setting can be managed in the /etc/systemd/system/tomcat.service file via the CATALINA_OPTS variable. This setting is defined in the file and referenced during tc Server startup in order to load environment variables. '
  desc  'rationale', ''
  desc  'check', "
    At the command prompt, run the following:

    # grep -i RECYCLE_FACADES /usr/lib/loginsight/application/3rd_party/apache-tomcat/conf/catalina.properties

    Example result:

    org.apache.catalina.connector.RECYCLE_FACADES=true

    If \"org.apache.catalina.connector.RECYCLE_FACADES\" is not set to \"true\", this is a finding.

    If the \"org.apache.catalina.connector.RECYCLE_FACADES\" setting does not exist, this is not a finding.
  "
  desc 'fix', "
    Navigate to and open:

    /usr/lib/loginsight/application/3rd_party/apache-tomcat/conf/catalina.properties

    Update or remove the following line:

    org.apache.catalina.connector.RECYCLE_FACADES=true

    Restart the service with the following command:

    # systemctl restart loginsight.service
  "
  impact 0.5
  tag severity: 'medium'
  tag gtitle: 'SRG-APP-000223-AS-000150'
  tag gid: 'V-VCFT-9X-000057'
  tag rid: 'SV-VCFT-9X-000057'
  tag stig_id: 'VCFT-9X-000057'
  tag cci: ['CCI-001664']
  tag nist: ['SC-23 (3)']

  describe parse_config_file("#{input('catalinaBase')}/conf/catalina.properties").params['org.apache.catalina.connector.RECYCLE_FACADES'] do
    it { should be_in [nil, 'true'] }
  end
end
