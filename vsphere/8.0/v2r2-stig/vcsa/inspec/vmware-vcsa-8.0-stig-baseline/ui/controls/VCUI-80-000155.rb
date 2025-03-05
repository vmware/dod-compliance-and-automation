control 'VCUI-80-000155' do
  title 'The vCenter UI service host-manager webapp must be removed.'
  desc 'Tomcat provides host management functionality through either a default host-manager webapp or through local editing of the configuration files. The host-manager webapp files must be deleted, and administration must be performed through the local editing of the configuration files.'
  desc 'check', 'At the command prompt, run the following command:

# ls -l /usr/lib/vmware-vsphere-ui/server/webapps/host-manager

If the host-manager folder exists or contains any content, this is a finding.'
  desc 'fix', 'At the command prompt, run the following command:

# rm -rf /usr/lib/vmware-vsphere-ui/server/webapps/host-manager'
  impact 0.5
  tag check_id: 'C-62876r1003679_chk'
  tag severity: 'medium'
  tag gid: 'V-259136'
  tag rid: 'SV-259136r1003680_rule'
  tag stig_id: 'VCUI-80-000155'
  tag gtitle: 'SRG-APP-000141-AS-000095'
  tag fix_id: 'F-62785r935311_fix'
  tag cci: ['CCI-000381']
  tag nist: ['CM-7 a']

  # Make sure the host-manager directory does not exist
  describe directory("#{input('tcCore')}/webapps/host-manager").exist? do
    it { should cmp 'false' }
  end
end
