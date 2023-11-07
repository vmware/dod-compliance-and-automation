control 'CNTR-K8-002011' do
  title 'Kubernetes must have a Pod Security Admission control file configured.'
  desc "An admission controller intercepts and processes requests to the Kubernetes API prior to persistence of the object, but after the request is authenticated and authorized.

Kubernetes (> v1.23)offers a built-in Pod Security admission controller to enforce the Pod Security Standards. Pod security restrictions are applied at the namespace level when pods are created.

The Kubernetes Pod Security Standards define different isolation levels for Pods. These standards let you define how you want to restrict the behavior of pods in a clear, consistent fashion."
  desc 'check', "Change to the /etc/kubernetes/manifests directory on the Kubernetes Control Plane. Run the command:

\"grep -i admission-control-config-file *\"

If the setting \"admission-control-config-file\" is not configured in the Kubernetes API Server manifest file, this is a finding.

Inspect the .yaml file defined by the --admission-control-config-file. Verify PodSecurity is properly configured.
If least privilege is not represented, this is a finding."
  desc 'fix', "Modify the file /etc/kubernetes/manifests/kube-apiserver.yaml and add the flag --admission-control-config-file (with a valid path for the file) to the apiserver configuration.

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
      enforce: \"privileged\"
      enforce-version: \"latest\"
    exemptions:
      # Don't forget to exempt namespaces or users that are responsible for deploying
      # cluster components, because they need to run privileged containers
      usernames: [\"admin\"]
      namespaces: [\"kube-system\"]

See For More Details:
Migrate from PSP to PSA:
https://kubernetes.io/docs/tasks/configure-pod-container/migrate-from-psp/

Best Practice: https://kubernetes.io/docs/concepts/security/pod-security-policy/#recommended-practice"
  impact 0.7
  tag severity: 'high'
  tag gtitle: 'SRG-APP-000342-CTR-000775'
  tag gid: 'V-254800'
  tag rid: 'SV-254800r864040_rule'
  tag stig_id: 'CNTR-K8-002011'
  tag fix_id: 'F-58357r863728_fix'
  tag cci: ['CCI-002263']
  tag nist: ['AC-16 a']

  unless kube_apiserver.exist?
    impact 0.0
    desc 'caveat', 'Kubernetes API Server process is not running on the target.'
  end

  describe kube_apiserver do
    its('admission-control-config-file') { should_not be nil }
  end
end
