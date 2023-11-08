control 'CNTR-K8-000350' do
  title 'The Kubernetes API server must have the secure port set.'
  desc "By default, the API server will listen on what is rightfully called the secure port, port 6443. Any requests to this port will perform authentication and authorization checks. If this port is disabled, anyone who gains access to the host on which the Control Plane is running has full control of the entire cluster over encrypted traffic.

Open the secure port by setting the API server's --secure-port flag to a value other than \"0\"."
  desc 'check', "Change to the /etc/kubernetes/manifests directory on the Kubernetes Control Plane. Run the command:

grep -i secure-port *

If the setting secure-port is set to \"0\" or is not configured in the Kubernetes API manifest file, this is a finding."
  desc 'fix', 'Edit the Kubernetes API Server manifest file in the /etc/kubernetes/manifests directory on the Kubernetes Control Plane. Set the argument --secure-port to a value greater than "0".'
  impact 0.5
  tag severity: 'medium'
  tag gtitle: 'SRG-APP-000033-CTR-000100'
  tag gid: 'V-242389'
  tag rid: 'SV-242389r863965_rule'
  tag stig_id: 'CNTR-K8-000350'
  tag fix_id: 'F-45622r863771_fix'
  tag cci: ['CCI-000213']
  tag nist: ['AC-3']

  unless kube_apiserver.exist?
    impact 0.0
    desc 'caveat', 'Kubernetes API Server process is not running on the target.'
  end

  describe kube_apiserver do
    its('secure-port') { should cmp > 0 }
  end
end
