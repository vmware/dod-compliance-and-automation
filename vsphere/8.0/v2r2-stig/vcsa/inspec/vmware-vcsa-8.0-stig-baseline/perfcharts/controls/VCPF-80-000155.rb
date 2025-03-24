control 'VCPF-80-000155' do
  title 'The vCenter Perfcharts service host-manager webapp must be removed.'
  desc 'Tomcat provides host management functionality through either a default host-manager webapp or through local editing of the configuration files. The host-manager webapp files must be deleted, and administration must be performed through the local editing of the configuration files.'
  desc 'check', 'At the command prompt, run the following command:

# ls -l /usr/lib/vmware-perfcharts/tc-instance/webapps/host-manager

If the host-manager folder exists or contains any content, this is a finding.'
  desc 'fix', 'At the command prompt, run the following command:

# rm -rf /usr/lib/vmware-perfcharts/tc-instance/webapps/host-manager'
  impact 0.5
  tag check_id: 'C-62843r1003624_chk'
  tag severity: 'medium'
  tag gid: 'V-259103'
  tag rid: 'SV-259103r1003625_rule'
  tag stig_id: 'VCPF-80-000155'
  tag gtitle: 'SRG-APP-000141-AS-000095'
  tag fix_id: 'F-62752r934966_fix'
  tag cci: ['CCI-000381']
  tag nist: ['CM-7 a']

  # Make sure the host-manager directory does not exist
  describe directory("#{input('appPath')}/webapps/host-manager").exist? do
    it { should cmp 'false' }
  end
end
