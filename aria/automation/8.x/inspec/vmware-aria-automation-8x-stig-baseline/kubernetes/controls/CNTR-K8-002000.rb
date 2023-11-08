control 'CNTR-K8-002000' do
  title 'The Kubernetes API server must have the ValidatingAdmissionWebhook enabled.'
  desc 'Enabling the admissions webhook allows for Kubernetes to apply policies against objects that are to be created, read, updated, or deleted. By applying a pod security policy, control can be given to not allow images to be instantiated that run as the root user. If pods run as the root user, the pod then has root privileges to the host system and all the resources it has. An attacker can use this to attack the Kubernetes cluster. By implementing a policy that does not allow root or privileged pods, the pod users are limited in what the pod can do and access.'
  desc 'check', "Prior to version 1.21, to enforce security policiesPod Security Policies (psp) were used. Those are now deprecated and will be removed from version 1.25.

Migrate from PSP to PSA:
https://kubernetes.io/docs/tasks/configure-pod-container/migrate-from-psp/

Pre-version 1.25 Check:
Change to the /etc/kubernetes/manifests directory on the Kubernetes Control Plane. Run the command:
grep -i ValidatingAdmissionWebhook *

If a line is not returned that includes enable-admission-plugins and ValidatingAdmissionWebhook, this is a finding."
  desc 'fix', "Edit the Kubernetes API Server manifest file in the /etc/kubernetes/manifests directory on the Kubernetes Control Plane. Set the argument \"--enable-admission-plugins\" to include \"ValidatingAdmissionWebhook\".  Each enabled plugin is separated by commas.

Note: It is best to implement policies first and then enable the webhook, otherwise a denial of service may occur."
  impact 0.7
  tag severity: 'high'
  tag gtitle: 'SRG-APP-000342-CTR-000775'
  tag gid: 'V-242436'
  tag rid: 'SV-242436r864011_rule'
  tag stig_id: 'CNTR-K8-002000'
  tag fix_id: 'F-45669r863897_fix'
  tag cci: ['CCI-002263']
  tag nist: ['AC-16 a']

  unless kube_apiserver.exist?
    impact 0.0
    desc 'caveat', 'Kubernetes API Server process is not running on the target.'
  end

  describe kube_apiserver do
    its('enable-admission-plugins.to_s') { should include 'ValidatingAdmissionWebhook' }
  end
end
