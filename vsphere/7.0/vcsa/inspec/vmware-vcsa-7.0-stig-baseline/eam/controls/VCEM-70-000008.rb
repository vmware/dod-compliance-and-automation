control 'VCEM-70-000008' do
  title 'ESX Agent Manager application files must be verified for their integrity.'
  desc 'Verifying that ESX Agent Manager application code is unchanged from its shipping state is essential for file validation and nonrepudiation of the ESX Agent Manager. There is no reason the MD5 hash of the RPM original files should be changed after installation, excluding configuration files.

'
  desc 'check', %q(At the command prompt, run the following command:

# rpm -V vmware-eam|grep "^..5......" | grep -v 'c /' | grep -v -E ".installer|.properties|.xml"

If there is any output, this is a finding.)
  desc 'fix', 'Reinstall the vCenter Server Appliance (VCSA) or roll back to a backup. Modifying the EAM installation files manually is not supported by VMware.'
  impact 0.5
  tag check_id: 'C-60355r918903_chk'
  tag severity: 'medium'
  tag gid: 'V-256680'
  tag rid: 'SV-256680r918904_rule'
  tag stig_id: 'VCEM-70-000008'
  tag gtitle: 'SRG-APP-000131-WSR-000051'
  tag fix_id: 'F-60298r888595_fix'
  tag satisfies: ['SRG-APP-000131-WSR-000051', 'SRG-APP-000357-WSR-000150']
  tag cci: ['CCI-001749', 'CCI-001849']
  tag nist: ['CM-5 (3)', 'AU-4']

  describe command("rpm -V vmware-eam|grep \"^..5......\" | grep -v 'c /' | grep -v -E \".installer|.properties|.xml\"") do
    its('stdout.strip') { should eq '' }
  end
end
