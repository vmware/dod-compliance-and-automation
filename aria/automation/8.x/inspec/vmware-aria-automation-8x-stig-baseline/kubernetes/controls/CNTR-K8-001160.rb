control 'CNTR-K8-001160' do
  title 'Secrets in Kubernetes must not be stored as environment variables.'
  desc 'Secrets, such as passwords, keys, tokens, and certificates should not be stored as environment variables. These environment variables are accessible inside Kubernetes by the "Get Pod" API call, and by any system, such as CI/CD pipeline, which has access to the definition file of the container. Secrets must be mounted from files or stored within password vaults.'
  desc 'check', "On the Kubernetes Control Plane, run the following command:
kubectl get all -o jsonpath='{range .items[?(@..secretKeyRef)]} {.kind} {.metadata.name} {\"\\n\"}{end}' -A

If any of the values returned reference environment variables, this is a finding."
  desc 'fix', 'Any secrets stored as environment variables must be moved to the secret files with the proper protections and enforcements or placed within a password vault.'
  impact 0.7
  tag severity: 'high'
  tag gtitle: 'SRG-APP-000171-CTR-000435'
  tag gid: 'V-242415'
  tag rid: 'SV-242415r863991_rule'
  tag stig_id: 'CNTR-K8-001160'
  tag fix_id: 'F-45648r712600_fix'
  tag cci: ['CCI-000196']
  tag nist: ['IA-5 (1) (c)']

  kubeconfig = input('kubectl_conf_path')
  describe command("kubectl get all --kubeconfig=#{kubeconfig} -o jsonpath=\'{range .items[?(@..secretKeyRef)]} {.metadata.namespace} {.kind}/{.metadata.name}{end}\' --all-namespaces") do
    its('stdout') { should be_empty }
  end
end
