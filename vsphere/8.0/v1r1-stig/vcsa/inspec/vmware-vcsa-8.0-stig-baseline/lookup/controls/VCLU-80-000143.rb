control 'VCLU-80-000143' do
  title 'The vCenter Lookup service default documentation must be removed.'
  desc 'Tomcat provides documentation and other directories in the default installation that do not serve a production use. These files must be deleted.'
  desc 'check', 'At the command prompt, run the following command:

# ls -l /var/opt/apache-tomcat/webapps/docs

If the "docs" folder exists or contains any content, this is a finding.'
  desc 'fix', 'At the command prompt, run the following command:

# rm -rf /var/opt/apache-tomcat/webapps/docs'
  impact 0.5
  tag check_id: 'C-62805r934851_chk'
  tag severity: 'medium'
  tag gid: 'V-259065'
  tag rid: 'SV-259065r934853_rule'
  tag stig_id: 'VCLU-80-000143'
  tag gtitle: 'SRG-APP-000141-AS-000095'
  tag fix_id: 'F-62714r934852_fix'
  tag cci: ['CCI-000381']
  tag nist: ['CM-7 a']

  # Make sure the docs directory does not exist
  describe directory("#{input('tcCore')}/webapps/docs").exist? do
    it { should cmp 'false' }
  end
end
