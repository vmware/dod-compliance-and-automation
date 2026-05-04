control 'VCPF-80-000154' do
  title 'The vCenter Perfcharts service manager webapp must be removed.'
  desc 'Tomcat provides management functionality through either a default manager webapp or through local editing of the configuration files. The manager webapp files must be deleted, and administration must be performed through the local editing of the configuration files.'
  desc 'check', 'At the command prompt, run the following command:

# ls -l /usr/lib/vmware-perfcharts/tc-instance/webapps/manager

If the manager folder exists or contains any content, this is a finding.'
  desc 'fix', 'At the command prompt, run the following command:

# rm -rf /usr/lib/vmware-perfcharts/tc-instance/webapps/manager'
  impact 0.5
  tag check_id: 'C-62842r934962_chk'
  tag severity: 'medium'
  tag gid: 'V-259102'
  tag rid: 'SV-259102r960963_rule'
  tag stig_id: 'VCPF-80-000154'
  tag gtitle: 'SRG-APP-000141-AS-000095'
  tag fix_id: 'F-62751r934963_fix'
  tag cci: ['CCI-000381']
  tag nist: ['CM-7 a']

  # Make sure the manager directory does not exist
  describe directory("#{input('appPath')}/webapps/manager").exist? do
    it { should cmp 'false' }
  end
end
