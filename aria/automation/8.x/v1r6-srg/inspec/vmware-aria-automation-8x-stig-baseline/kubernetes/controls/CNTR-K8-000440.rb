control 'CNTR-K8-000440' do
  title 'The Kubernetes kubelet staticPodPath must not enable static pods.'
  desc 'Allowing kubelet to set a staticPodPath gives containers with root access permissions to traverse the hosting filesystem. The danger comes when the container can create a manifest file within the /etc/kubernetes/manifests directory. When a manifest is created within this directory, containers are entirely governed by the Kubelet not the API Server. The container is not susceptible to admission control at all. Any containers or pods that are instantiated in this manner are called "static pods" and are meant to be used for pods such as the API server, scheduler, controller, etc., not workload pods that need to be governed by the API Server.'
  desc 'check', 'Ensure that Kubernetes static PodPath is not enabled on each Control Plane and Worker node.

On the Control Plane and Worker nodes, run the command:
ps -ef | grep kubelet

Note the path to the config file (identified by --config).

Run the command:
grep -i staticPodPath <path_to_config_file>

If any of the Control Plane and Worker nodes return a value for "staticPodPath", this is a finding.'
  desc 'fix', 'On each Control Plane and Worker node, run the command:
ps -ef | grep kubelet

Note the path to the config file (identified by --config).

Edit the Kubernetes kubelet file in the --config directory on the Kubernetes Control Plane and Worker nodes. Remove the setting "staticPodPath".

Restart the kubelet service using the following command:
systemctl daemon-reload && systemctl restart kubelet'
  impact 0.7
  ref 'DPMS Target Kubernetes'
  tag check_id: 'C-45672r927091_chk'
  tag severity: 'high'
  tag gid: 'V-242397'
  tag rid: 'SV-242397r927245_rule'
  tag stig_id: 'CNTR-K8-000440'
  tag gtitle: 'SRG-APP-000033-CTR-000090'
  tag fix_id: 'F-45630r927092_fix'
  tag 'documentable'
  tag cci: ['CCI-000213']
  tag nist: ['AC-3']

  kubelet_conf_path = input('kubelet_conf_path')

  if kubelet_conf_path
    describe kubelet_config_file(kubelet_conf_path) do
      its('staticPodPath') { should be nil }
    end
  else
    describe kubelet_config_file do
      its('staticPodPath') { should be nil }
    end
  end
end
