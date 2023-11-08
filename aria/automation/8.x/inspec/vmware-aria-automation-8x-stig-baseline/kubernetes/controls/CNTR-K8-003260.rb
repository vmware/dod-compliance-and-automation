control 'CNTR-K8-003260' do
  title 'The Kubernetes etcd must have file permissions set to 644 or more restrictive.'
  desc 'The Kubernetes etcd key-value store provides a way to store data to the Control Plane. If these files can be changed, data to API object and Control Plane would be compromised.'
  desc 'check', "Review the permissions of the Kubernetes etcd by using the command:

stat -c %a  /var/lib/etcd/*

If any of the files are have permissions more permissive than \"644\", this is a finding."
  desc 'fix', "Change the permissions of the manifest files to \"644\" by executing the command:

chmod 644/var/lib/etcd/*"
  impact 0.5
  tag severity: 'medium'
  tag gtitle: 'SRG-APP-000516-CTR-001335'
  tag gid: 'V-242459'
  tag rid: 'SV-242459r864024_rule'
  tag stig_id: 'CNTR-K8-003260'
  tag fix_id: 'F-45692r712732_fix'
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']

  unless etcd.exist?
    impact 0.0
    desc 'caveat', 'Kubernetes ETCD Server process is not running on the target.'
  end

  etcd_files = command('find /var/lib/etcd/ -type f').stdout.split

  if etcd_files.empty?
    desc 'caveat', 'Kubernetes ETCD files not present of the target at specified path.'
    describe 'Kubernetes ETCD files not present of the target at specified path.' do
      skip
    end
  end

  etcd_files.each do |file_name|
    describe file(file_name) do
      it { should_not be_more_permissive_than('0644') }
    end
  end
end
