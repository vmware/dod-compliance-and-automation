control 'VCLU-70-000008' do
  title 'Lookup Service application files must be verified for their integrity.'
  desc 'Verifying the Lookup Service application code is unchanged from its shipping state is essential for file validation and nonrepudiation of the Lookup Service. There is no reason the MD5 hash of the RPM original files should be changed after installation, excluding configuration files.'
  desc 'check', 'At the command prompt, run the following command:

# rpm -V vmware-lookupsvc|grep "^..5......"|grep -E "\\.war|\\.jar|\\.sh|\\.py"

If there is any output, this is a finding.'
  desc 'fix', 'Reinstall the vCenter Server Appliance (VCSA) or roll back to a backup. VMware does not support modifying the Lookup Service installation files manually.'
  impact 0.5
  tag check_id: 'C-60388r888728_chk'
  tag severity: 'medium'
  tag gid: 'V-256713'
  tag rid: 'SV-256713r888730_rule'
  tag stig_id: 'VCLU-70-000008'
  tag gtitle: 'SRG-APP-000131-WSR-000051'
  tag fix_id: 'F-60331r888729_fix'
  tag cci: ['CCI-001749']
  tag nist: ['CM-5 (3)']

  describe command('rpm -V vmware-lookupsvc|grep "^..5......"|grep -E "\.war|\.jar|\.sh|\.py"') do
    its('stdout.strip') { should eq '' }
  end
end
