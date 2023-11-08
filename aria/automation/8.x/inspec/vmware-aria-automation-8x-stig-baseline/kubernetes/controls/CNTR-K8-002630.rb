control 'CNTR-K8-002630' do
  title 'Kubernetes API Server must disable token authentication to protect information in transit.'
  desc 'Kubernetes token authentication uses password known as secrets in a plaintext file. This file contains sensitive information such as token, username and user uid. This token is used by service accounts within pods to authenticate with the API Server. This information is very valuable for attackers with malicious intent if the service account is privileged having access to the token. With this token a threat actor can impersonate the service account gaining access to the Rest API service.'
  desc 'check', "Change to the /etc/kubernetes/manifests/ directory on the Kubernetes Control Plane. Run the command:
grep -i token-auth-file *

If \"token-auth-file\" is set in the Kubernetes API server manifest file, this is a finding."
  desc 'fix', 'Edit the Kubernetes API Server manifest file in the /etc/kubernetes/manifests directory on the Kubernetes Control Plane. Remove parameter "--token-auth-file".'
  impact 0.5
  tag severity: 'medium'
  tag gtitle: 'SRG-APP-000439-CTR-001080'
  tag gid: 'V-245543'
  tag rid: 'SV-245543r864034_rule'
  tag stig_id: 'CNTR-K8-002630'
  tag fix_id: 'F-48773r863947_fix'
  tag cci: ['CCI-002448']
  tag nist: ['SC-12 (3)']

  unless kube_apiserver.exist?
    impact 0.0
    desc 'caveat', 'Kubernetes API Server process is not running on the target.'
  end

  describe kube_apiserver do
    its('token-auth-file') { should be_nil }
  end
end
