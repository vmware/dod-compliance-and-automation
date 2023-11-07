control 'VCEM-80-000154' do
  title 'The vCenter ESX Agent Manager service manager webapp must be removed.'
  desc 'Tomcat provides management functionality through either a default manager webapp or through local editing of the configuration files. The manager webapp files must be deleted, and administration must be performed through the local editing of the configuration files.'
  desc 'check', 'At the command prompt, run the following command:

# ls -l /var/opt/apache-tomcat/webapps/manager

If the manager folder exists or contains any content, this is a finding.'
  desc 'fix', 'At the command prompt, run the following command:

# rm -rf /var/opt/apache-tomcat/webapps/manager'
  impact 0.5
  tag check_id: 'C-62775r934761_chk'
  tag severity: 'medium'
  tag gid: 'V-259035'
  tag rid: 'SV-259035r934763_rule'
  tag stig_id: 'VCEM-80-000154'
  tag gtitle: 'SRG-APP-000141-AS-000095'
  tag fix_id: 'F-62684r934762_fix'
  tag cci: ['CCI-000381']
  tag nist: ['CM-7 a']

  # Make sure the manager directory does not exist
  describe directory("#{input('tcCore')}/webapps/manager").exist? do
    it { should cmp 'false' }
  end
end
