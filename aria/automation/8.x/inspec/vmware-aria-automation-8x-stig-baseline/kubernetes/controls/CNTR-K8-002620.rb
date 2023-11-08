control 'CNTR-K8-002620' do
  title 'Kubernetes API Server must disable basic authentication to protect information in transit.'
  desc 'Kubernetes basic authentication sends and receives request containing username, uid, groups, and other fields over a clear text HTTP communication. Basic authentication does not provide any security mechanisms using encryption standards. PKI certificate-based authentication must be set over a secure channel to ensure confidentiality and integrity. Basic authentication must not be set in the manifest file.'
  desc 'check', "Change to the /etc/kubernetes/manifests/ directory on the Kubernetes Control Plane. Run the command:
grep -i basic-auth-file *

If \"basic-auth-file\" is set in the Kubernetes API server manifest file this is a finding."
  desc 'fix', 'Edit the Kubernetes API Server manifest file in the /etc/kubernetes/manifests directory on the Kubernetes Control Plane. Remove the setting "--basic-auth-file".'
  impact 0.7
  tag severity: 'high'
  tag gtitle: 'SRG-APP-000439-CTR-001080'
  tag gid: 'V-245542'
  tag rid: 'SV-245542r864033_rule'
  tag stig_id: 'CNTR-K8-002620'
  tag fix_id: 'F-48772r863944_fix'
  tag cci: ['CCI-002448']
  tag nist: ['SC-12 (3)']

  unless kube_apiserver.exist?
    impact 0.0
    desc 'caveat', 'Kubernetes API Server process is not running on the target.'
  end

  describe kube_apiserver do
    its('basic-auth-file') { should be_nil }
  end
end
