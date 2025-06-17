control 'VCFT-9X-000140' do
  title 'The VMware Cloud Foundation Operations for Logs Loginsight service example applications must be removed.'
  desc  'Apache Tomcat provides example applications, documentation, and other directories in the default installation that do not serve a production use. These files must be deleted.'
  desc  'rationale', ''
  desc  'check', "
    At the command prompt, run the following:

    # ls -l /usr/lib/loginsight/application/3rd_party/apache-tomcat/webapps/examples

    If the examples folder exists or contains any content, this is a finding.
  "
  desc 'fix', "
    At the command prompt, run the following:

    # rm -rf /usr/lib/loginsight/application/3rd_party/apache-tomcat/webapps/examples
  "
  impact 0.5
  tag severity: 'medium'
  tag gtitle: 'SRG-APP-000516-AS-000237'
  tag gid: 'V-VCFT-9X-000140'
  tag rid: 'SV-VCFT-9X-000140'
  tag stig_id: 'VCFT-9X-000140'
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']

  # Make sure the examples directory does not exist
  describe directory("#{input('catalinaBase')}/webapps/examples").exist? do
    it { should cmp 'false' }
  end
end
