control 'VRLT-8X-000141' do
  title 'The VMware Aria Operations for Logs tc Server must remove example applications.'
  desc  'tc Server provides example applications, documentation, and other directories in the default installation which do not serve a production use. These files must be deleted.'
  desc  'rationale', ''
  desc  'check', "
    At the command prompt, run the following command:

    # ls -l /usr/lib/loginsight/application/3rd_party/apache-tomcat/webapps/examples

    If the examples folder exists or contains any content, this is a finding.
  "
  desc 'fix', "
    At the command prompt, run the following command:

    # rm -rf /usr/lib/loginsight/application/3rd_party/apache-tomcat/webapps/examples
  "
  impact 0.5
  tag severity: 'medium'
  tag gtitle: 'SRG-APP-000141-AS-000095'
  tag gid: 'V-VRLT-8X-000141'
  tag rid: 'SV-VRLT-8X-000141'
  tag stig_id: 'VRLT-8X-000141'
  tag cci: ['CCI-000381']
  tag nist: ['CM-7 a']

  # Make sure the examples directory does not exist
  describe directory("#{input('catalinaBase')}/webapps/examples").exist? do
    it { should cmp 'false' }
  end
end
