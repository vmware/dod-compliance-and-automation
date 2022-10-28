control 'VCEM-70-000008' do
  title 'ESX Agent Manager application files must be verified for their integrity.'
  desc  'Verifying that ESX Agent Manager application code is unchanged from its shipping state is essential for file validation and non-repudiation of the ESX Agent Manager itself. There is no reason that the MD5 hash of the rpm original files should be changed after installation, excluding configuration files.'
  desc  'rationale', ''
  desc  'check', "
    At the command prompt, execute the following command:

    # rpm -V vmware-eam|grep \"^..5......\"|grep -v -E \"\\.installer|\\.properties|\\.xml\"

    If there is any output, this is a finding.
  "
  desc 'fix', 'Reinstall the VCSA or roll back to a backup. Modifying the EAM installation files manually is not supported by VMware.'
  impact 0.5
  tag severity: 'medium'
  tag gtitle: 'SRG-APP-000131-WSR-000051'
  tag satisfies: ['SRG-APP-000357-WSR-000150']
  tag gid: nil
  tag rid: nil
  tag stig_id: 'VCEM-70-000008'
  tag cci: ['CCI-001749', 'CCI-001849']
  tag nist: ['AU-4', 'CM-5 (3)']

  describe command('rpm -V vmware-eam|grep "^..5......"|grep -v -E "\.installer|\.properties|\.xml"') do
    its('stdout.strip') { should eq '' }
  end
end
