control 'VCFT-9X-000145' do
  title 'The VMware Cloud Foundation Operations for Logs Loginsight service host-manager webapp must be removed.'
  desc  'Apache Tomcat provides host management functionality through either a default host-manager webapp or through local editing of the configuration files. The host-manager webapp files must be deleted, and administration must be performed through the local editing of the configuration files.'
  desc  'rationale', ''
  desc  'check', "
    At the command prompt, run the following:

    # ls -l /usr/lib/loginsight/application/3rd_party/apache-tomcat/webapps/host-manager

    If the manager folder exists or contains any content, this is a finding.
  "
  desc 'fix', "
    At the command prompt, run the following:

    # rm -rf /usr/lib/loginsight/application/3rd_party/apache-tomcat/webapps/host-manager
  "
  impact 0.5
  tag severity: 'medium'
  tag gtitle: 'SRG-APP-000516-AS-000237'
  tag gid: 'V-VCFT-9X-000145'
  tag rid: 'SV-VCFT-9X-000145'
  tag stig_id: 'VCFT-9X-000145'
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']

  # Make sure the examples directory does not exist
  describe directory("#{input('catalinaBase')}/webapps/host-manager").exist? do
    it { should cmp 'false' }
  end
end
