control 'VCLU-70-000008' do
  title 'Lookup Service application files must be verified for their integrity.'
  desc  "Verifying that the Lookup Service application code is unchanged from it's shipping state is essential for file validation and nonrepudiation of the Lookup Service itself. There is no reason that the MD5 hash of the rpm original files should be changed after installation, excluding configuration files."
  desc  'rationale', ''
  desc  'check', "
    At the command prompt, execute the following command:

    # rpm -V vmware-lookupsvc|grep \"^..5......\"|grep -E \"\\.war|\\.jar|\\.sh|\\.py\"

    If there is any output, this is a finding.
  "
  desc 'fix', 'Reinstall the VCSA or roll back to a backup. Modifying the Lookup Service installation files manually is not supported by VMware.'
  impact 0.5
  tag severity: 'medium'
  tag gtitle: 'SRG-APP-000131-WSR-000051'
  tag gid: nil
  tag rid: nil
  tag stig_id: 'VCLU-70-000008'
  tag cci: ['CCI-001749']
  tag nist: ['CM-5 (3)']

  describe command('rpm -V vmware-lookupsvc|grep "^..5......"|grep -E "\.war|\.jar|\.sh|\.py"') do
    its('stdout.strip') { should eq '' }
  end
end
