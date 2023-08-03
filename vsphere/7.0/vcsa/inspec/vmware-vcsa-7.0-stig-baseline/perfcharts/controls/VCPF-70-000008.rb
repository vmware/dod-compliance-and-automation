control 'VCPF-70-000008' do
  title 'Performance Charts application files must be verified for their integrity.'
  desc 'Verifying the Security Token Service application code is unchanged from its shipping state is essential for file validation and nonrepudiation of Performance Charts. There is no reason the MD5 hash of the RPM original files should be changed after installation, excluding configuration files.'
  desc 'check', 'At the command prompt, run the following command:

# rpm -V VMware-perfcharts|grep "^..5......"|grep -v -E "\\.properties|\\.conf|\\.xml|\\.password"

If any files are returned, this is a finding.'
  desc 'fix', 'Reinstall the vCenter Server Appliance (VCSA) or roll back to a backup. VMware does not support modifying the Performance Charts installation files manually.'
  impact 0.5
  tag check_id: 'C-60293r888343_chk'
  tag severity: 'medium'
  tag gid: 'V-256618'
  tag rid: 'SV-256618r888345_rule'
  tag stig_id: 'VCPF-70-000008'
  tag gtitle: 'SRG-APP-000131-WSR-000051'
  tag fix_id: 'F-60236r888344_fix'
  tag cci: ['CCI-001749']
  tag nist: ['CM-5 (3)']

  describe command('rpm -V VMware-perfcharts|grep "^..5......"|grep -v -E "\.properties|\.conf|\.xml|\.password"') do
    its('stdout.strip') { should eq '' }
  end
end
