control 'VCUI-70-000008' do
  title 'vSphere UI application files must be verified for their integrity.'
  desc  'Verifying that the vSphere UI application code is unchanged from its shipping state is essential for file validation and non-repudiation of the vSphere UI. There is no reason that the MD5 hash of the rpm original files should be changed after installation, excluding configuration files.'
  desc  'rationale', ''
  desc  'check', "
    At the command prompt, execute the following command:

    # rpm -V vsphere-ui|grep \"^..5......\"|grep -v -E \"\\.prop|\\.pass|\\.xml\"

    If is any output, this is a finding.
  "
  desc 'fix', "
    Reinstall the VCSA or roll back to a snapshot.

    Modifying the vSphere UI installation files manually is not supported by VMware.
  "
  impact 0.5
  tag severity: 'medium'
  tag gtitle: 'SRG-APP-000131-WSR-000051'
  tag gid: nil
  tag rid: nil
  tag stig_id: 'VCUI-70-000008'
  tag cci: ['CCI-001749']
  tag nist: ['CM-5 (3)']

  describe command('rpm -V vsphere-ui|grep "^..5......"|grep -v -E "\.prop|\.pass|\.xml"') do
    its('stdout.strip') { should eq '' }
  end
end
