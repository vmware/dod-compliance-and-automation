control 'CNTR-K8-000370' do
  title 'The Kubernetes Kubelet must have anonymous authentication disabled.'
  desc "A user who has access to the Kubelet essentially has root access to the nodes contained within the Kubernetes Control Plane. To control access, users must be authenticated and authorized. By allowing anonymous connections, the controls put in place to secure the Kubelet can be bypassed.

Setting anonymous authentication to \"false\" also disables unauthenticated requests from kubelets.

While there are instances where anonymous connections may be needed (e.g., health checks) and Role-Based Access Controls (RBAC) are in place to limit the anonymous access, this access must be disabled and only enabled when necessary."
  desc 'check', "Run the following command on each Worker Node:
ps -ef | grep kubelet

Verify that the --anonymous-auth argument exists and is set to \"false\".

If the --anonymous-auth argument exists and is not set to \"false\", this is a finding.

If the --anonymous-auth argument does not exist, check the Control Plane Kubelet config file:
On the Kubernetes Control Plane, run the command:
ps -ef | grep kubelet
Check the config file (path identified by: --config).

Verify \"authentication: anonymous: enabled=false\". If this is not set to \"false\", this is a finding.

If \"--anonymous-auth=false\" argument does not exist on the worker nodes or \"authentication: anonymous: enabled=false\" does not exist on the Control Plane, this is a finding."
  desc 'fix', "Edit the Kubernetes Kubelet file in the --config directory on the Kubernetes Control Plane:
Set \"authentication: anonymous: enabled=false\"

If using worker node arguments, edit the kubelet service file (identified in the --config directory):
On each Worker Node:
set the parameter in KUBELET_SYSTEM_PODS_ARGS variable to
\"--anonymous-auth=false\".

Reset Kubelet service using the following command:
service kubelet restart"
  impact 0.7
  tag severity: 'high'
  tag gtitle: 'SRG-APP-000033-CTR-000090'
  tag gid: 'V-242391'
  tag rid: 'SV-242391r863967_rule'
  tag stig_id: 'CNTR-K8-000370'
  tag fix_id: 'F-45624r863777_fix'
  tag cci: ['CCI-000213']
  tag nist: ['AC-3']

  kubelet_conf_path = input('kubelet_conf_path')

  if kubelet_conf_path
    describe.one do
      describe kubelet do
        its('anonymous-auth') { should cmp 'false' }
      end
      describe kubelet_config_file(kubelet_conf_path) do
        its(['authentication', 'anonymous', 'enabled']) { should cmp 'false' }
      end
    end
  else
    describe.one do
      describe kubelet do
        its('anonymous-auth') { should cmp 'false' }
      end
      describe kubelet_config_file do
        its(['authentication', 'anonymous', 'enabled']) { should cmp 'false' }
      end
    end
  end
end
