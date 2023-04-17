control 'CNTR-K8-001440' do
  title 'Kubernetes API Server must have a certificate for communication.'
  desc "Kubernetes control plane and external communication is managed by API Server. The main implementation of the API Server is to manage hardware resources for pods and container using horizontal or vertical scaling. Anyone who can access the API Server can effectively control the Kubernetes architecture. Using authenticity protection, the communication can be protected against man-in-the-middle attacks/session hijacking and the insertion of false information into sessions.

The communication session is protected by utilizing transport encryption protocols, such as TLS. TLS provides the Kubernetes API Server with a means to be able to authenticate sessions and encrypt traffic.

To enable encrypted communication for API Server, the parameter etcd-cafile must be set. This parameter gives the location of the SSL Certificate Authority file used to secure API Server communication."
  desc 'check', "Change to the /etc/kubernetes/manifests/ directory on the Kubernetes Control Plane. Run the command:
grep -i tls-cert-file *
grep -i tls-private-key-file *

If the setting tls-cert-file and private-key-file is not set in the Kubernetes API server manifest file or contains no value, this is a finding."
  desc 'fix', 'Edit the Kubernetes API Server manifest file in the /etc/kubernetes/manifests directory on the Kubernetes Control Plane. Set the value of tls-cert-file and tls-private-key-file to path containing Approved Organizational Certificate.'
  impact 0.5
  tag severity: 'medium'
  tag gtitle: 'SRG-APP-000219-CTR-000550'
  tag gid: 'V-242422'
  tag rid: 'SV-242422r863997_rule'
  tag stig_id: 'CNTR-K8-001440'
  tag fix_id: 'F-45655r863855_fix'
  tag cci: ['CCI-001184']
  tag nist: ['SC-23']

  unless kube_apiserver.exist?
    impact 0.0
    desc 'caveat', 'Kubernetes API Server process is not running on the target.'
  end

  describe kube_apiserver do
    its('tls-cert-file') { should_not be_nil }
    its('tls-private-key-file') { should_not be_nil }
  end
end
