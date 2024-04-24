control 'CNTR-K8-003110' do
  title 'The Kubernetes component manifests must be owned by root.'
  desc 'The Kubernetes manifests are those files that contain the arguments and settings for the Control Plane services. These services are etcd, the api server, controller, proxy, and scheduler. If these files can be changed, the scheduler will be implementing the changes immediately. Many of the security settings within the document are implemented through these manifests.'
  desc 'check', 'Review the ownership of the Kubernetes manifests files by using the command:

stat -c %U:%G /etc/kubernetes/manifests/* | grep -v root:root

If the command returns any non root:root file permissions, this is a finding.'
  desc 'fix', 'Change the ownership of the manifest files to root: root by executing the command:

chown root:root /etc/kubernetes/manifests/*'
  impact 0.5
  ref 'DPMS Target Kubernetes'
  tag check_id: 'C-45719r712686_chk'
  tag severity: 'medium'
  tag gid: 'V-242444'
  tag rid: 'SV-242444r879887_rule'
  tag stig_id: 'CNTR-K8-003110'
  tag gtitle: 'SRG-APP-000516-CTR-001325'
  tag fix_id: 'F-45677r712687_fix'
  tag 'documentable'
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']

  manifests_path = input('manifests_path')

  if kube_apiserver.exist?
    manifests_files = command("find #{manifests_path} -type f").stdout.split
    if !manifests_files.empty?
      manifests_files.each do |file_name|
        describe file(file_name) do
          its('owner') { should cmp 'root' }
          its('group') { should cmp 'root' }
        end
      end
    else
      describe "Kubernetes manifest files not present of the target at specified path #{manifests_path}." do
        skip "Kubernetes manifest files not present of the target at specified path #{manifests_path}."
      end
    end
  else
    impact 0.0
    describe 'This control does not apply to worker nodes so this is not applicable.' do
      skip 'This control does not apply to worker nodes so this is not applicable.'
    end
  end
end
