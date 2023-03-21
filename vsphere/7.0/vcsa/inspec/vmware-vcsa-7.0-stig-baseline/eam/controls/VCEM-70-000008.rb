control 'VCEM-70-000008' do
  title 'ESX Agent Manager application files must be verified for their integrity.'
  desc  'Verifying that ESX Agent Manager application code is unchanged from its shipping state is essential for file validation and nonrepudiation of the ESX Agent Manager. There is no reason the MD5 hash of the RPM original files should be changed after installation, excluding configuration files.'
  desc  'rationale', ''
  desc  'check', "
    At the command prompt, run the following command:

    # rpm -V vmware-eam|grep \"^..5......\"|grep -v -E \"\\.installer|\\.properties|\\.xml\"

    If there is any output, this is a finding.
  "
  desc 'fix', 'Reinstall the vCenter Server Appliance (VCSA) or roll back to a backup. Modifying the EAM installation files manually is not supported by VMware.'
  impact 0.5
  tag severity: 'medium'
  tag gtitle: 'SRG-APP-000131-WSR-000051'
  tag satisfies: ['SRG-APP-000357-WSR-000150']
  tag gid: 'V-256680'
  tag rid: 'SV-256680r888596_rule'
  tag stig_id: 'VCEM-70-000008'
  tag cci: ['CCI-001749', 'CCI-001849']
  tag nist: ['AU-4', 'CM-5 (3)']

  describe command('rpm -V vmware-eam|grep "^..5......"|grep -v -E "\.installer|\.properties|\.xml"') do
    its('stdout.strip') { should eq '' }
  end
end
