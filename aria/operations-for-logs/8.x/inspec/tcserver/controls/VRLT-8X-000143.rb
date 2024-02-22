control 'VRLT-8X-000143' do
  title 'The VMware Aria Operations for Logs tc Server documentation must be removed.'
  desc  'tc Server provides documentation and other directories in the default installation which do not serve a production use. These files must be deleted.'
  desc  'rationale', ''
  desc  'check', "
    At the command prompt, run the following command:

    # ls -l /usr/lib/loginsight/application/3rd_party/apache-tomcat/webapps/docs

    If the docs folder exists or contains any content, this is a finding.
  "
  desc 'fix', "
    At the command prompt, run the following command:

    # rm -rf /usr/lib/loginsight/application/3rd_party/apache-tomcat/webapps/docs
  "
  impact 0.5
  tag severity: 'medium'
  tag gtitle: 'SRG-APP-000141-AS-000095'
  tag gid: 'V-VRLT-8X-000143'
  tag rid: 'SV-VRLT-8X-000143'
  tag stig_id: 'VRLT-8X-000143'
  tag cci: ['CCI-000381']
  tag nist: ['CM-7 a']

  # Make sure the docs directory does not exist
  describe directory("#{input('catalinaBase')}/webapps/docs").exist? do
    it { should cmp 'false' }
  end
end
