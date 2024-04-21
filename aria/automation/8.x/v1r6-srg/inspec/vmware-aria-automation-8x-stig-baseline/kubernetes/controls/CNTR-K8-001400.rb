control 'CNTR-K8-001400' do
  title 'The Kubernetes API server must use approved cipher suites.'
  desc 'The Kubernetes API server communicates to the kubelet service on the nodes to deploy, update, and delete resources. If an attacker were able to get between this communication and modify the request, the Kubernetes cluster could be compromised. Using approved cypher suites for the communication ensures the protection of the transmitted information, confidentiality, and integrity so that the attacker cannot read or alter this communication.'
  desc 'check', 'Change to the /etc/kubernetes/manifests/ directory on the Kubernetes Control Plane. Run the command:
grep -i tls-cipher-suites *

If the setting feature tls-cipher-suites is not set in the Kubernetes API server manifest file or contains no value or does not contain TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256,TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384,TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384, this is a finding.'
  desc 'fix', 'Edit the Kubernetes API Server manifest file in the /etc/kubernetes/manifests directory on the Kubernetes Control Plane.

Set the value of "--tls-cipher-suites" to:
"TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256,TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384,TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384"'
  impact 0.5
  ref 'DPMS Target Kubernetes'
  tag check_id: 'C-45693r863842_chk'
  tag severity: 'medium'
  tag gid: 'V-242418'
  tag rid: 'SV-242418r927250_rule'
  tag stig_id: 'CNTR-K8-001400'
  tag gtitle: 'SRG-APP-000219-CTR-000550'
  tag fix_id: 'F-45651r927105_fix'
  tag 'documentable'
  tag cci: ['CCI-001184']
  tag nist: ['SC-23']

  approved_cipher_suites = input('approved_cipher_suites')

  if kube_apiserver.exist?
    describe kube_apiserver do
      its('tls_cipher_suites') { should contain_exactly(*approved_cipher_suites) }
    end
  else
    impact 0.0
    describe 'The Kubernetes API server process is not running on the target so this control is not applicable.' do
      skip 'The Kubernetes API server process is not running on the target so this control is not applicable.'
    end
  end
end
