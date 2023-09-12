control 'VRPI-8X-000143' do
  title 'The API service default documentation must be removed.'
  desc  'Tomcat provides documentation and other directories in the default installation that do not serve a production use. These files must be deleted.'
  desc  'rationale', ''
  desc  'check', "
    At the command prompt, run the following command:

    # ls -l $CATALINA_BASE/webapps/docs

    If the \"docs\" folder exists or contains any content, this is a finding.
  "
  desc 'fix', "
    At the command prompt, run the following command:

    # rm -rf $CATALINA_BASE/webapps/docs
  "
  impact 0.5
  tag severity: 'medium'
  tag gtitle: 'SRG-APP-000141-AS-000095'
  tag gid: 'V-VRPI-8X-000143'
  tag rid: 'SV-VRPI-8X-000143'
  tag stig_id: 'VRPI-8X-000143'
  tag cci: ['CCI-000381']
  tag nist: ['CM-7 a']

  # Make sure the docs directory does not exist
  describe directory("#{input('api-tcInstance')}/webapps/docs").exist? do
    it { should cmp 'false' }
  end
end
