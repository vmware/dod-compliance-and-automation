control 'CNTR-K8-003150' do
  title 'The Kubernetes Kube Proxy must be owned by root.'
  desc 'The Kubernetes kube proxy kubeconfig contain the argument and setting for the Control Planes. These settings contain network rules for restricting network communication between pods, clusters, and networks. If these files can be changed, data traversing between the Kubernetes Control Panel components would be compromised. Many of the security settings within the document are implemented through this file.'
  desc 'check', "Check if Kube-Proxy is running use the following command:
ps -ef | grep kube-proxy

If Kube-Proxy exists:
Review the permissions of the Kubernetes Kube Proxy by using the command:
stat -c   %U:%G &lt;location from --kubeconfig&gt;| grep -v root:root

If the command returns any non root:root file permissions, this is a finding."
  desc 'fix', "Change the ownership of the Kube Proxy to root:root by executing the command:

chown root:root &lt;location from kubeconfig&gt;."
  impact 0.5
  tag severity: 'medium'
  tag gtitle: 'SRG-APP-000516-CTR-001325'
  tag gid: 'V-242448'
  tag rid: 'SV-242448r864020_rule'
  tag stig_id: 'CNTR-K8-003150'
  tag fix_id: 'F-45681r712699_fix'
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']

  unless kube_proxy.exist?
    impact 0.0
    desc 'caveat', 'Kube-Proxy process is not running on the target.'
  end

  kubeproxy_kubeconfig_file = kube_proxy.kubeconfig_file

  if kubeproxy_kubeconfig_file.nil?
    describe 'kube-proxy kubeconfig not found...skipping...' do
      skip 'kube-proxy kubeconfig not found...skipping...'
    end
  else
    describe kube_proxy do
      its('kubeconfig_file') { should be_owned_by('root') }
      its('kubeconfig_file') { should be_grouped_into('root') }
    end
  end
end
