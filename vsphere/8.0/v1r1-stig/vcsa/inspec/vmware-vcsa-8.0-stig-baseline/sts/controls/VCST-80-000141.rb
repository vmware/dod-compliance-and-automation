control 'VCST-80-000141' do
  title 'The vCenter STS service example applications must be removed.'
  desc 'Tomcat provides example applications, documentation, and other directories in the default installation that do not serve a production use. These files must be deleted.'
  desc 'check', 'At the command prompt, run the following command:

# ls -l /var/opt/apache-tomcat/webapps/examples

If the examples folder exists or contains any content, this is a finding.'
  desc 'fix', 'At the command prompt, run the following command:

# rm -rf /var/opt/apache-tomcat/webapps/examples'
  impact 0.5
  tag check_id: 'C-62735r934641_chk'
  tag severity: 'medium'
  tag gid: 'V-258995'
  tag rid: 'SV-258995r934643_rule'
  tag stig_id: 'VCST-80-000141'
  tag gtitle: 'SRG-APP-000141-AS-000095'
  tag fix_id: 'F-62644r934642_fix'
  tag cci: ['CCI-000381']
  tag nist: ['CM-7 a']

  # Make sure the examples directory does not exist
  describe directory("#{input('tcCore')}/webapps/examples").exist? do
    it { should cmp 'false' }
  end
end
