control 'CNTR-K8-003190' do
  title 'The Kubernetes kubelet KubeConfig must have file permissions set to 644 or more restrictive.'
  desc 'The Kubernetes kubelet agent registers nodes with the API Server, mounts volume storage for pods, and performs health checks to containers within pods. If these files can be modified, the information system would be unaware of pod or container degradation. Many of the security settings within the document are implemented through this file.'
  desc 'check', 'Review the permissions of the Kubernetes Kubelet conf by using the command:

stat -c %a  /etc/kubernetes/kubelet.conf

If any of the files are have permissions more permissive than "644", this is a finding.'
  desc 'fix', 'Change the permissions of the Kubelet to "644" by executing the command:

chmod 644 /etc/kubernetes/kubelet.conf'
  impact 0.5
  ref 'DPMS Target Kubernetes'
  tag check_id: 'C-45727r712710_chk'
  tag severity: 'medium'
  tag gid: 'V-242452'
  tag rid: 'SV-242452r918197_rule'
  tag stig_id: 'CNTR-K8-003190'
  tag gtitle: 'SRG-APP-000516-CTR-001325'
  tag fix_id: 'F-45685r821615_fix'
  tag 'documentable'
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']

  kubelet_process = input('kubelet_process')

  describe kubelet(kubelet_process) do
    its('kubeconfig_file') { should_not be_nil }
    its('kubeconfig_file') { should_not be_more_permissive_than('0644') }
  end
end
