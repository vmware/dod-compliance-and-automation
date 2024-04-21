control 'CNTR-K8-003260' do
  title 'The Kubernetes etcd must have file permissions set to 644 or more restrictive.'
  desc 'The Kubernetes etcd key-value store provides a way to store data to the Control Plane. If these files can be changed, data to API object and Control Plane would be compromised.'
  desc 'check', 'Review the permissions of the Kubernetes etcd by using the command:

ls -AR /var/lib/etcd/*

If any of the files have permissions more permissive than "644", this is a finding.'
  desc 'fix', 'Change the permissions of the manifest files to "644" by executing the command:

chmod -R 644 /var/lib/etcd/*'
  impact 0.5
  ref 'DPMS Target Kubernetes'
  tag check_id: 'C-45734r918198_chk'
  tag severity: 'medium'
  tag gid: 'V-242459'
  tag rid: 'SV-242459r918200_rule'
  tag stig_id: 'CNTR-K8-003260'
  tag gtitle: 'SRG-APP-000516-CTR-001335'
  tag fix_id: 'F-45692r918199_fix'
  tag 'documentable'
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']

  if etcd.exist?
    etcd_files = command('find /var/lib/etcd/ -type f').stdout.split
    if !etcd_files.empty?
      etcd_files.each do |file_name|
        describe file(file_name) do
          it { should_not be_more_permissive_than('0644') }
        end
      end
    else
      describe 'No etcd files found with incorrect ownership.' do
        subject { etcd_files }
        it { should be_empty }
      end
    end
  else
    impact 0.0
    describe 'This control does not apply to worker nodes so this is not applicable.' do
      skip 'This control does not apply to worker nodes so this is not applicable.'
    end
  end
end
