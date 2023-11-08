control 'CNTR-K8-001990' do
  title 'Kubernetes must prevent non-privileged users from executing privileged functions to include disabling, circumventing, or altering implemented security safeguards/countermeasures or the installation of patches and updates.'
  desc "Kubernetes uses the API Server to control communication to the other services that makeup Kubernetes. The use of authorizations and not the default of \"AlwaysAllow\" enables the Kubernetes functions control to only the groups that need them.

To control access the API server must have one of the following options set for the authorization mode:
    --authorization-mode=ABAC Attribute-Based Access Control (ABAC) mode allows a user to configure policies using local files.
    --authorization-mode=RBAC Role-based access control (RBAC) mode allows a user to create and store policies using the Kubernetes API.
    --authorization-mode=Webhook

WebHook is an HTTP callback mode that allows a user to manage authorization using a remote REST endpoint.
    --authorization-mode=Node

Node authorization is a special-purpose authorization mode that specifically authorizes API requests made by kubelets.
    --authorization-mode=AlwaysDeny

This flag blocks all requests. Use this flag only for testing."
  desc 'check', "Change to the /etc/kubernetes/manifests directory on the Kubernetes Control Plane. Run the command:
grep -i authorization-mode *

If the setting authorization-mode is set to \"AlwaysAllow\" in the Kubernetes API Server manifest file or is not configured, this is a finding."
  desc 'fix', 'Edit the Kubernetes API Server manifest file in the /etc/kubernetes/manifests directory on the Kubernetes Control Plane. Set the argument "--authorization-mode" to any valid authorization mode other than AlwaysAllow.'
  impact 0.7
  tag severity: 'high'
  tag gtitle: 'SRG-APP-000340-CTR-000770'
  tag satisfies: ['SRG-APP-000340-CTR-000770', 'SRG-APP-000033-CTR-000095', 'SRG-APP-000378-CTR-000880']
  tag gid: 'V-242435'
  tag rid: 'SV-242435r864010_rule'
  tag stig_id: 'CNTR-K8-001990'
  tag fix_id: 'F-45668r863894_fix'
  tag cci: ['CCI-000213', 'CCI-001842', 'CCI-002265']
  tag nist: ['AC-3', 'AU-1 b 2', 'AC-16 b']

  unless kube_apiserver.exist?
    impact 0.0
    desc 'caveat', 'Kubernetes API Server process is not running on the target.'
  end

  describe kube_apiserver do
    its('authorization-mode') { should_not be_nil }
    its('authorization-mode') { should_not cmp 'AlwaysAllow' }
  end
end
