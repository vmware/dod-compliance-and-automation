control 'CNTR-K8-000370' do
  title 'The Kubernetes Kubelet must have anonymous authentication disabled.'
  desc 'A user who has access to the Kubelet essentially has root access to the nodes contained within the Kubernetes Control Plane. To control access, users must be authenticated and authorized. By allowing anonymous connections, the controls put in place to secure the Kubelet can be bypassed.

Setting anonymous authentication to "false" also disables unauthenticated requests from kubelets.

While there are instances where anonymous connections may be needed (e.g., health checks) and Role-Based Access Controls (RBAC) are in place to limit the anonymous access, this access must be disabled and only enabled when necessary.'
  desc 'check', 'On each Control Plane and Worker Node, run the command:
ps -ef | grep kubelet

If the "--anonymous-auth" option exists, this is a finding.

Note the path to the config file (identified by --config).

Inspect the content of the config file:
Locate the "anonymous" section under "authentication".  In this section, if the field "enabled" does not exist or is set to "true", this is a finding.'
  desc 'fix', 'On each Control Plane and Worker Node, run the command:
ps -ef | grep kubelet

Remove the "anonymous-auth" option if present.

Note the path to the config file (identified by --config).

Edit the config file:
Locate the "authentication" section and the "anonymous" subsection. Within the "anonymous" subsection, set "enabled" to "false".

Restart the kubelet service using the following command:
systemctl daemon-reload && systemctl restart kubelet'
  impact 0.7
  ref 'DPMS Target Kubernetes'
  tag check_id: 'C-45666r918150_chk'
  tag severity: 'high'
  tag gid: 'V-242391'
  tag rid: 'SV-242391r918152_rule'
  tag stig_id: 'CNTR-K8-000370'
  tag gtitle: 'SRG-APP-000033-CTR-000090'
  tag fix_id: 'F-45624r918151_fix'
  tag 'documentable'
  tag cci: ['CCI-000213']
  tag nist: ['AC-3']

  kubelet_process = input('kubelet_process')
  kubelet_conf_path = input('kubelet_conf_path')

  describe kubelet(kubelet_process) do
    its('anonymous-auth') { should be nil }
  end
  if kubelet_conf_path
    describe kubelet_config_file(kubelet_conf_path) do
      its(['authentication', 'anonymous', 'enabled']) { should cmp 'false' }
    end
  else
    describe kubelet_config_file do
      its(['authentication', 'anonymous', 'enabled']) { should cmp 'false' }
    end
  end
end
