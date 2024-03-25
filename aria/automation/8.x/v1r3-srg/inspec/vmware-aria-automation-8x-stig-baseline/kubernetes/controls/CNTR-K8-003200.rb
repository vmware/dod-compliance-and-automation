control 'CNTR-K8-003200' do
  title 'The Kubernetes kubelet config must be owned by root.'
  desc 'The Kubernetes kubelet agent registers nodes with the API server and performs health checks to containers within pods. If these files can be modified, the information system would be unaware of pod or container degradation. Many of the security settings within the document are implemented through this file.'
  desc 'check', "Review the Kubernetes Kubelet conf files by using the command:

stat -c %U:%G /etc/kubernetes/kubelet.conf| grep -v root:root

If the command returns any non root:root file permissions, this is a finding."
  desc 'fix', "Change the ownership of the kubelet.conf to root: root by executing the command:

chown root:root /etc/kubernetes/kubelet.conf"
  impact 0.5
  tag severity: 'medium'
  tag gtitle: 'SRG-APP-000516-CTR-001325'
  tag gid: 'V-242453'
  tag rid: 'SV-242453r712715_rule'
  tag stig_id: 'CNTR-K8-003200'
  tag fix_id: 'F-45686r712714_fix'
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']

  kubelet_kubeconf_path = input('kubelet_kubeconf_path')

  if kubelet_kubeconf_path
    describe.one do
      describe kubelet do
        its('kubeconfig_file') { should_not be_nil }
        its('kubeconfig_file') { should be_owned_by('root') }
        its('kubeconfig_file') { should be_grouped_into('root') }
      end
      describe file(kubelet_kubeconf_path) do
        it { should be_owned_by('root') }
        it { should be_grouped_into('root') }
      end
    end
  else
    describe kubelet do
      its('kubeconfig_file') { should_not be_nil }
      its('kubeconfig_file') { should be_owned_by('root') }
      its('kubeconfig_file') { should be_grouped_into('root') }
    end
  end
end
