control 'VCPF-70-000008' do
  title 'Performance Charts application files must be verified for their integrity.'
  desc  "Verifying that the Security Token Service application code is unchanged from it's shipping state is essential for file validation and nonrepudiation of Performance Charts. There is no reason that the MD5 hash of the rpm original files should be changed after installation, excluding configuration files."
  desc  'rationale', ''
  desc  'check', "
    At the command prompt, execute the following command:

    # rpm -V VMware-perfcharts|grep \"^..5......\"|grep -v -E \"\\.properties|\\.conf|\\.xml|\\.password\"

    If any files are returned, this is a finding.
  "
  desc 'fix', 'Reinstall the VCSA or roll back to a backup. Modifying the Performance Charts installation files manually is not supported by VMware.'
  impact 0.5
  tag severity: 'medium'
  tag gtitle: 'SRG-APP-000131-WSR-000051'
  tag gid: nil
  tag rid: nil
  tag stig_id: 'VCPF-70-000008'
  tag cci: ['CCI-001749']
  tag nist: ['CM-5 (3)']

  describe command('rpm -V VMware-perfcharts|grep "^..5......"|grep -v -E "\.properties|\.conf|\.xml|\.password"') do
    its('stdout.strip') { should eq '' }
  end
end
