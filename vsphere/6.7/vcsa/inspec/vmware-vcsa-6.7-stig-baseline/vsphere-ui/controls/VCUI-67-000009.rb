control 'VCUI-67-000009' do
  title 'vSphere UI plugins must be authorized before use.'
  desc  "The vSphere UI ships with a number of plugins out of the box. Any
additional plugins may affect the availability and integrity of the system and
must be approved and documented by the ISSO before deployment."
  desc  'rationale', ''
  desc  'check', "
    At the command prompt, execute the following command:

    # diff <(find
/usr/lib/vmware-vsphere-ui/plugin-packages/vsphere-client/plugins -type f|sort)
<(rpm -ql vsphere-ui|grep
\"/usr/lib/vmware-vsphere-ui/plugin-packages/vsphere-client/plugins/\"|sort)

    If there is any output, this indicates a vSphere UI plugin is present that
does not ship with the VCSA.

    If this plugin is not known and approved, this is a finding.
  "
  desc  'fix', "
    For every unauthorized plugin returned by the check, run the following
command.

    # rm <file>
  "
  impact 0.5
  tag severity: 'medium'
  tag gtitle: 'SRG-APP-000131-WSR-000073'
  tag gid: 'V-239690'
  tag rid: 'SV-239690r679176_rule'
  tag stig_id: 'VCUI-67-000009'
  tag fix_id: 'F-42882r679175_fix'
  tag cci: ['CCI-001749']
  tag nist: ['CM-5 (3)']

  describe command('diff <(find /usr/lib/vmware-vsphere-ui/plugin-packages/vsphere-client/plugins -type f|sort) <(rpm -ql vsphere-ui|grep "/usr/lib/vmware-vsphere-ui/plugin-packages/vsphere-client/plugins/"|sort)') do
    its('stdout.strip') { should eq '' }
  end
end
