control 'TCSV-00-000057' do
  title 'tc Server must be configured to limit data exposure between applications.'
  desc  'If RECYCLE_FACADES is true or if a security manager is in use, a new facade object will be created for each request. This reduces the chances that a bug in an application might expose data from one request to another. This setting is configured using environment variable settings. For Linux OS flavors other than Ubuntu, use the relevant OS commands. For Ubuntu, this setting can be managed in the /etc/systemd/system/tomcat.service file via the CATALINA_OPTS variable. This setting is defined in the file and referenced during tc Server startup in order to load environment variables. '
  desc  'rationale', ''
  desc  'check', "
    At the command prompt, run the following commands:

    # grep -i RECYCLE_FACADES $CATALINA_BASE/conf/catalina.properties

    If there are no results, or if 'org.apache.catalina.connector.RECYCLE_FACADES' is not set to true, this is a finding.
  "
  desc 'fix', "
    Edit the $CATALINA_BASE/conf/catalina.properties file.

    Ensure the 'org.apache.catalina.connector.RECYCLE_FACADES' line is present, and is set to true.

    EXAMPLE catalina.properties:
    ...
    org.apache.catalina.startup.EXIT_ON_INIT_FAILURE=true
    org.apache.catalina.connector.RECYCLE_FACADES=true
    ...

    Restart the service:
    # systemctl restart loginsight.service
  "
  impact 0.5
  tag severity: 'medium'
  tag gtitle: 'SRG-APP-000223-AS-000150'
  tag satisfies: ['SRG-APP-000516-AS-000237']
  tag gid: 'V-TCSV-00-000057'
  tag rid: 'SV-TCSV-00-000057'
  tag stig_id: 'TCSV-00-000057'
  tag cci: %w(CCI-000366 CCI-001664)
  tag nist: ['CM-6 b', 'SC-23 (3)']

  # Check catalina.properties file
  props = parse_config(file("#{input('catalinaBase')}/conf/catalina.properties").content).params['org.apache.catalina.connector.RECYCLE_FACADES']

  describe props do
    it { should cmp 'true' }
  end
end
