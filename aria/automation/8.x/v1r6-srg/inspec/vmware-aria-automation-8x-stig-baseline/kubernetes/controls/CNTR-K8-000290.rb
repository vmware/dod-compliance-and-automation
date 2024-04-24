control 'CNTR-K8-000290' do
  title 'User-managed resources must be created in dedicated namespaces.'
  desc 'Creating namespaces for user-managed resources is important when implementing Role-Based Access Controls (RBAC). RBAC allows for the authorization of users and helps support proper API server permissions separation and network micro segmentation. If user-managed resources are placed within the default namespaces, it becomes impossible to implement policies for RBAC permission, service account usage, network policies, and more.'
  desc 'check', 'To view the available namespaces, run the command:

kubectl get namespaces

The default namespaces to be validated are default, kube-public, and kube-node-lease if it is created.

For the default namespace, execute the commands:

kubectl config set-context --current --namespace=default
kubectl get all

For the kube-public namespace, execute the commands:

kubectl config set-context --current --namespace=kube-public
kubectl get all

For the kube-node-lease namespace, execute the commands:

kubectl config set-context --current --namespace=kube-node-lease
kubectl get all

The only valid return values are the kubernetes service (i.e., service/kubernetes) and nothing at all.

If a return value is returned from the "kubectl get all" command and it is not the kubernetes service (i.e., service/kubernetes), this is a finding.'
  desc 'fix', 'Move any user-managed resources from the default, kube-public, and kube-node-lease namespaces to user namespaces.'
  impact 0.7
  ref 'DPMS Target Kubernetes'
  tag check_id: 'C-45658r863752_chk'
  tag severity: 'high'
  tag gid: 'V-242383'
  tag rid: 'SV-242383r879533_rule'
  tag stig_id: 'CNTR-K8-000290'
  tag gtitle: 'SRG-APP-000038-CTR-000105'
  tag fix_id: 'F-45616r863753_fix'
  tag 'documentable'
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']

  kubeconfig = input('kubectl_conf_path')
  # Can be empty on worker nodes
  describe command("kubectl get all --no-headers -n default -o name --kubeconfig=#{kubeconfig}") do
    its('stdout.strip') { should be_empty.or cmp 'service/kubernetes' }
  end

  describe command("kubectl get all --no-headers -n kube-public -o name --kubeconfig=#{kubeconfig}") do
    its('stdout') { should be_empty }
  end

  describe command("kubectl get all --no-headers -n kube-node-lease -o name --kubeconfig=#{kubeconfig}") do
    its('stdout') { should be_empty }
  end
end
