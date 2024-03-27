control 'CNTR-K8-001360' do
  title 'Kubernetes must separate user functionality.'
  desc 'Separating user functionality from management functionality is a requirement for all the components within the Kubernetes Control Plane. Without the separation, users may have access to management functions that can degrade the Kubernetes architecture and the services being offered, and can offer a method to bypass testing and validation of functions before introduced into a production environment.'
  desc 'check', "On the Control Plane, run the command:
kubectl get pods --all-namespaces

Review the namespaces and pods that are returned. Kubernetes system namespaces are kube-node-lease, kube-public, and kube-system.

If any user pods are present in the Kubernetes system namespaces, this is a finding."
  desc 'fix', 'Move any user pods that are present in the Kubernetes system namespaces to user specific namespaces.'
  impact 0.5
  tag severity: 'medium'
  tag gtitle: 'SRG-APP-000211-CTR-000530'
  tag gid: 'V-242417'
  tag rid: 'SV-242417r863992_rule'
  tag stig_id: 'CNTR-K8-001360'
  tag fix_id: 'F-45650r712606_fix'
  tag cci: ['CCI-001082']
  tag nist: ['SC-2']

  describe 'Verify user pods are not present in the Kubernetes system namespaces.' do
    skip 'This is a manual check.'
  end
end
