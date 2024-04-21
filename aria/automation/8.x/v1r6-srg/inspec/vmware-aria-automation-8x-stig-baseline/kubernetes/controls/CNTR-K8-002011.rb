control 'CNTR-K8-002011' do
  title 'Kubernetes must have a Pod Security Admission control file configured.'
  desc 'An admission controller intercepts and processes requests to the Kubernetes API prior to persistence of the object, but after the request is authenticated and authorized.

Kubernetes (> v1.23)offers a built-in Pod Security admission controller to enforce the Pod Security Standards. Pod security restrictions are applied at the namespace level when pods are created.

The Kubernetes Pod Security Standards define different isolation levels for Pods. These standards define how to restrict the behavior of pods in a clear, consistent fashion.'
  desc 'check', 'Change to the /etc/kubernetes/manifests directory on the Kubernetes Control Plane. Run the command:

"grep -i admission-control-config-file *"

If the setting "--admission-control-config-file" is not configured in the Kubernetes API Server manifest file, this is a finding.

Inspect the .yaml file defined by the --admission-control-config-file. Verify PodSecurity is properly configured.
If least privilege is not represented, this is a finding.'
  desc 'fix', %q(Edit the Kubernetes API Server manifest file in the /etc/kubernetes/manifests directory on the Kubernetes Control Plane.

Set the value of "--admission-control-config-file" to a valid path for the file.

Create an admission controller config file:
Example File:
```yaml
apiVersion: apiserver.config.k8s.io/v1
kind: AdmissionConfiguration
plugins:
- name: PodSecurity
  configuration:
    apiVersion: pod-security.admission.config.k8s.io/v1beta1
    kind: PodSecurityConfiguration
    # Defaults applied when a mode label is not set.
    defaults:
      enforce: "privileged"
      enforce-version: "latest"
    exemptions:
      # Don't forget to exempt namespaces or users that are responsible for deploying
      # cluster components, because they need to run privileged containers
      usernames: ["admin"]
      namespaces: ["kube-system"]

See for more details:
Migrate from PSP to PSA:
https://kubernetes.io/docs/tasks/configure-pod-container/migrate-from-psp/

Best Practice: https://kubernetes.io/docs/concepts/security/pod-security-policy/#recommended-practice.)
  impact 0.7
  ref 'DPMS Target Kubernetes'
  tag check_id: 'C-58411r927123_chk'
  tag severity: 'high'
  tag gid: 'V-254800'
  tag rid: 'SV-254800r927257_rule'
  tag stig_id: 'CNTR-K8-002011'
  tag gtitle: 'SRG-APP-000342-CTR-000775'
  tag fix_id: 'F-58357r927124_fix'
  tag 'documentable'
  tag cci: ['CCI-002263']
  tag nist: ['AC-16 a']

  pod_security_admission_namespace_exemptions = input('pod_security_admission_namespace_exemptions')
  pod_security_admission_user_exemptions = input('pod_security_admission_user_exemptions')
  pod_security_admission_runtime_exemptions = input('pod_security_admission_runtime_exemptions')

  if kube_apiserver.exist?
    server_version = Semverse::Version.new(bash("kubelet --version | awk -F' ' '{ print $2 }' |sed s/^v//").stdout.chomp)
    server_version_major = server_version.major
    server_version_minor = server_version.minor
    if server_version_major.to_i >= 1 && server_version_minor.to_i > 23
      admissioncontrolfile = kube_apiserver.params['admission-control-config-file'][0]
      yamlControlConfig = yaml(admissioncontrolfile)
      describe yamlControlConfig do
        its('kind') { should cmp 'AdmissionConfiguration' }
      end
      if yamlControlConfig['plugins'].nil?
        describe yamlControlConfig do
          its('plugins') { should_not be_nil }
        end
      else
        match = false
        yamlControlConfig['plugins'].each do |plugin|
          next unless plugin['name'] == 'PodSecurity'
          match = true
          describe plugin do
            its(['configuration', 'apiVersion']) { should cmp 'pod-security.admission.config.k8s.io/v1' }
            its(['configuration', 'kind']) { should cmp 'PodSecurityConfiguration' }
            its(['configuration', 'defaults', 'enforce']) { should cmp('baseline').or cmp('restricted') }
            its(['configuration', 'defaults', 'enforce-version']) { should cmp('latest').or be nil }
            its(['configuration', 'exemptions', 'namespaces']) { should cmp(pod_security_admission_namespace_exemptions).or (be_empty).or be nil }
            its(['configuration', 'exemptions', 'usernames']) { should cmp(pod_security_admission_user_exemptions).or (be_empty).or be nil }
            its(['configuration', 'exemptions', 'runtimeClasses']) { should cmp(pod_security_admission_runtime_exemptions).or (be_empty).or be nil }
          end
        end
        unless match
          describe 'No Podsecurity Plugin found.' do
            subject { match }
            it { should be true }
          end
        end
      end
    else
      impact 0.0
      describe 'This control is not applicable to Kubernetes 1.23 and below.' do
        skip 'This control is not applicable to Kubernetes 1.23 and below.'
      end
    end
  else
    impact 0.0
    describe 'This control does not apply to worker nodes so this is not applicable.' do
      skip 'This control does not apply to worker nodes so this is not applicable.'
    end
  end
end
