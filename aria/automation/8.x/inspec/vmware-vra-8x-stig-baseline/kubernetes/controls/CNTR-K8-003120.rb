control 'CNTR-K8-003120' do
  title 'The Kubernetes component etcd must be owned by etcd.'
  desc 'The Kubernetes etcd key-value store provides a way to store data to the Control Plane. If these files can be changed, data to API object and the Control Plane would be compromised. The scheduler will implement the changes immediately. Many of the security settings within the document are implemented through this file.'
  desc 'check', "Review the ownership of the Kubernetes etcd files by using the command:

stat -c %U:%G /var/lib/etcd/* | grep -v etcd:etcd

If the command returns any non etcd:etcd file permissions, this is a finding."
  desc 'fix', "Change the ownership of the manifest files to etcd:etcd by executing the command:

chown etcd:etcd /var/lib/etcd/*"
  impact 0.5
  tag severity: 'medium'
  tag gtitle: 'SRG-APP-000516-CTR-001325'
  tag gid: 'V-242445'
  tag rid: 'SV-242445r864017_rule'
  tag stig_id: 'CNTR-K8-003120'
  tag fix_id: 'F-45678r712690_fix'
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']

  unless etcd.exist?
    impact 0.0
    desc 'caveat', 'Kubernetes ETCD Server process is not running on the target.'
  end

  # Instead of finding each file we are looking for incorrect files since .snap files can disappear in the middle of a check.
  etcd_files = command('find /var/lib/etcd/ -type f "(" ! -user etcd -o ! -group etcd ")"').stdout.split

  if etcd_files.empty?
    describe 'No ETCD files found with incorrect ownership. Returned files' do
      subject { etcd_files }
      it { should be_empty }
    end
  else
    etcd_files.each do |file_name|
      describe file(file_name) do
        it { should be_owned_by('etcd') }
        it { should be_grouped_into('etcd') }
      end
    end
  end
end
