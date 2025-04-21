control 'VCUI-70-000009' do
  title 'vSphere UI plugins must be authorized before use.'
  desc 'The vSphere UI ships with a number of plugins out of the box. Any additional plugins may affect the availability and integrity of the system and must be approved and documented by the information system security officer (ISSO) before deployment.'
  desc 'check', 'At the command prompt, run the following command:

# diff <(find /usr/lib/vmware-vsphere-ui/plugin-packages/vsphere-client/plugins -type f|sort) <(rpm -ql vsphere-ui|grep "/usr/lib/vmware-vsphere-ui/plugin-packages/vsphere-client/plugins/"|sort)

If there is any output, this indicates a vSphere UI plugin is present that does not ship with the vCenter Server Appliance (VCSA).

If this plugin is not known and approved, this is a finding.'
  desc 'fix', 'For every unauthorized plugin returned by the check, run the following command:

# rm <file>'
  impact 0.5
  tag check_id: 'C-60461r889355_chk'
  tag severity: 'medium'
  tag gid: 'V-256786'
  tag rid: 'SV-256786r889357_rule'
  tag stig_id: 'VCUI-70-000009'
  tag gtitle: 'SRG-APP-000131-WSR-000073'
  tag fix_id: 'F-60404r889356_fix'
  tag cci: ['CCI-001749']
  tag nist: ['CM-5 (3)']

  describe command('diff <(find /usr/lib/vmware-vsphere-ui/plugin-packages/vsphere-client/plugins -type f|sort) <(rpm -ql vsphere-ui|grep "/usr/lib/vmware-vsphere-ui/plugin-packages/vsphere-client/plugins/"|sort)') do
    its('stdout.strip') { should eq '' }
  end
end
