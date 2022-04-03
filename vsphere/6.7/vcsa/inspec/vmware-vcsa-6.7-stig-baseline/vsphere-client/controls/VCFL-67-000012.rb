control 'VCFL-67-000012' do
  title 'vSphere Client application files must be verified for their integrity.'
  desc  "Verifying that vSphere Client application code is unchanged from its
shipping state is essential for file validation and non-repudiation of vSphere
Client. There is no reason that the MD5 hash of the rpm original files should
be changed after installation, excluding configuration files."
  desc  'rationale', ''
  desc  'check', "
    At the command prompt, execute the following command:

    # rpm -V vsphere-client|grep \"^..5......\"|grep -E
\"\\.war|\\.jar|\\.sh|\\.py\"

    If there is any output, this is a finding.
  "
  desc 'fix', "
    Reinstall the VCSA or roll back to a snapshot.

    Modifying the vSphere Client installation files manually is not supported
by VMware.
  "
  impact 0.5
  tag severity: 'medium'
  tag gtitle: 'SRG-APP-000131-WSR-000051'
  tag gid: 'V-239753'
  tag rid: 'SV-239753r679486_rule'
  tag stig_id: 'VCFL-67-000012'
  tag fix_id: 'F-42945r679485_fix'
  tag cci: ['CCI-001749']
  tag nist: ['CM-5 (3)']

  command('find /storage/log/vmware/vsphere-client/logs/ -maxdepth 1 -type f').stdout.split.each do |fname|
    describe file(fname) do
      it { should_not be_more_permissive_than('0600') }
      its('owner') { should eq 'vsphere-client' }
      its('group') { should eq 'users' }
    end
  end
end
