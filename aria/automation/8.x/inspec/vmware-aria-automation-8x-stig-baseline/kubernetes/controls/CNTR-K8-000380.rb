control 'CNTR-K8-000380' do
  title 'The Kubernetes kubelet must enable explicit authorization.'
  desc 'Kubelet is the primary agent on each node. The API server communicates with each kubelet to perform tasks such as starting/stopping pods. By default, kubelets allow all authenticated requests, even anonymous ones, without requiring any authorization checks from the API server. This default behavior bypasses any authorization controls put in place to limit what users may perform within the Kubernetes cluster. To change this behavior, the default setting of AlwaysAllow for the authorization mode must be set to "Webhook".'
  desc 'check', "Run the following command on each Worker Node:
ps -ef | grep kubelet

Verify that the --authorization-mode exists and is set to \"Webhook\".

If the --authorization-mode argument exists and is not set to \"Webhook\", this is a finding.

If the --authorization-mode does not exist, check the Control Plane Kubelet config file:
On the Kubernetes Control Plane, run the command:
ps -ef | grep kubelet
Check the config file (path identified by: --config).

Verify authorization: mode. If this is not set to \"Webhook\", this is a finding.

If \"--authorization-mode=Webhook\" argument does not exist on the worker nodes or \"authorization: mode=Webhook\" does not exist on the Control Plane, this is a finding."
  desc 'fix', "Edit the Kubernetes Kubelet file in the --config directory on the Kubernetes Control Plane:
Set the argument \"authorization: mode=Webhook\"

If using worker node arguments, edit the kubelet service file identified in the --config directory:
On each Worker Node: set the parameter in KUBELET_SYSTEM_PODS_ARGS variable to
\"--authorization-mode=Webhook\".

Reset Kubelet service using the following command:
service kubelet restart"
  impact 0.7
  tag severity: 'high'
  tag gtitle: 'SRG-APP-000033-CTR-000095'
  tag gid: 'V-242392'
  tag rid: 'SV-242392r863968_rule'
  tag stig_id: 'CNTR-K8-000380'
  tag fix_id: 'F-45625r863780_fix'
  tag cci: ['CCI-000213']
  tag nist: ['AC-3']

  kubelet_conf_path = input('kubelet_conf_path')

  if kubelet_conf_path
    describe.one do
      describe kubelet do
        its('authorization-mode') { should cmp 'Webhook' }
      end
      describe kubelet_config_file(kubelet_conf_path) do
        its(['authorization', 'mode']) { should cmp 'Webhook' }
      end
    end
  else
    describe.one do
      describe kubelet do
        its('authorization-mode') { should cmp 'Webhook' }
      end
      describe kubelet_config_file do
        its(['authorization', 'mode']) { should cmp 'Webhook' }
      end
    end
  end
end
